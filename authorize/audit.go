package authorize

import (
	"context"
	"errors"
	"math/rand"
	"net/http"
	"sync"
	"time"

	envoy_service_auth_v2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	"github.com/google/btree"
	ulid "github.com/oklog/ulid/v2"
	"golang.org/x/sync/errgroup"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/signal"
	"github.com/pomerium/pomerium/pkg/grpc/audit"
)

const (
	auditRecordCollectionDegree  = 32
	auditRecordCollectionMaxSize = 10000
)

type (
	auditRecordCollection struct {
		mu     sync.RWMutex
		tree   *btree.BTree
		signal *signal.Signal
	}
	auditRecordCollectionItem struct {
		record *audit.Record
	}
)

func (item auditRecordCollectionItem) Less(than btree.Item) bool {
	other, ok := than.(auditRecordCollectionItem)
	if !ok {
		return false
	}

	switch {
	case item.record.GetId() < other.record.GetId():
		return true
	case item.record.GetId() > other.record.GetId():
		return false
	}

	return false
}

func newAuditRecordCollection() *auditRecordCollection {
	return &auditRecordCollection{
		tree:   btree.New(auditRecordCollectionDegree),
		signal: signal.New(),
	}
}

func (c *auditRecordCollection) add(record *audit.Record) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// remove the oldest record if we've hit the limit
	if c.tree.Len() >= auditRecordCollectionMaxSize {
		c.tree.DeleteMin()
	}

	c.tree.ReplaceOrInsert(auditRecordCollectionItem{record: record})
	c.signal.Broadcast()
}

func (c *auditRecordCollection) list(after string) []*audit.Record {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var records []*audit.Record
	c.tree.AscendGreaterOrEqual(auditRecordCollectionItem{record: &audit.Record{Id: after}}, func(i btree.Item) bool {
		record := i.(auditRecordCollectionItem).record
		if record.Id != after {
			records = append(records, record)
		}
		return true
	})
	return records
}

func (c *auditRecordCollection) remove(recordID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.tree.Delete(auditRecordCollectionItem{record: &audit.Record{Id: recordID}})
}

// RetrieveAuditRecords retrieves audit records.
func (a *Authorize) RetrieveAuditRecords(srv audit.AuditService_RetrieveAuditRecordsServer) error {
	eg, ctx := errgroup.WithContext(srv.Context())

	// read confirmation receipts and remove audit records that correspond to those receipts
	eg.Go(func() error {
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			confirm, err := srv.Recv()
			if err != nil {
				return err
			}

			a.auditRecords.remove(confirm.Id)
		}
	})

	// send audit records
	eg.Go(func() error {
		ready := a.auditRecords.signal.Bind()
		defer a.auditRecords.signal.Unbind(ready)

		var lastID string
		for {
			records := a.auditRecords.list(lastID)
			for _, r := range records {
				err := srv.Send(r)
				if err != nil {
					return err
				}
				if r.Id > lastID {
					lastID = r.Id
				}
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ready:
			}
		}
	})

	err := eg.Wait()
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		err = nil
	}
	return err
}

var auditRecordIDEntropy = ulid.Monotonic(rand.New(rand.NewSource(time.Now().UnixNano())), 0)

func nextAuditRecordID() string {
	// we use a monotonically increasing uuid so that records are returned in order
	return ulid.MustNew(ulid.Timestamp(time.Now()), auditRecordIDEntropy).String()
}

func (a *Authorize) getAuditRecord(
	req *envoy_service_auth_v2.CheckRequest,
	res *envoy_service_auth_v2.CheckResponse,
	reply *evaluator.Result,
	sessionState *sessions.State,
) *audit.Record {
	hreq := req.GetAttributes().GetRequest().GetHttp()
	u := getCheckRequestURL(req)

	record := &audit.Record{
		Id:   nextAuditRecordID(),
		Time: req.GetAttributes().GetRequest().GetTime(),
		AuthenticationInfo: &audit.AuthenticationInfo{
			IdpProvider: a.currentOptions.Load().Provider,
		},
		Source: u.String(),
		Request: &audit.Record_HttpRequest{HttpRequest: &audit.HTTPRequest{
			Id:       hreq.GetId(),
			Method:   hreq.GetMethod(),
			Headers:  hreq.GetHeaders(),
			Path:     hreq.GetPath(),
			Host:     hreq.GetHost(),
			Scheme:   hreq.GetScheme(),
			Query:    hreq.GetQuery(),
			Fragment: hreq.GetFragment(),
			Size:     hreq.GetSize(),
			Protocol: hreq.GetProtocol(),
			Body:     hreq.GetBody(),
		}},
		Status: &audit.Status{
			Message: res.GetStatus().GetMessage(),
			Code:    res.GetStatus().GetCode(),
		},
	}
	if reply.MatchingPolicy != nil {
		record.Destination = reply.MatchingPolicy.Destination.String()
	}
	if sessionState != nil {
		record.AuthenticationInfo.SessionId = sessionState.ID
		record.AuthenticationInfo.IdpSubject = sessionState.Subject
	}
	if hres := res.GetOkResponse(); hres != nil {
		hdrs := make(map[string]string)
		for _, hdr := range hres.GetHeaders() {
			hdrs[hdr.Header.Key] = hdr.Header.Value
		}
		record.Response = &audit.Record_HttpResponse{HttpResponse: &audit.HTTPResponse{
			StatusCode: http.StatusOK,
			Headers:    hdrs,
		}}
	}
	if hres := res.GetDeniedResponse(); hres != nil {
		hdrs := make(map[string]string)
		for _, hdr := range hres.GetHeaders() {
			hdrs[hdr.Header.Key] = hdr.Header.Value
		}
		record.Response = &audit.Record_HttpResponse{HttpResponse: &audit.HTTPResponse{
			StatusCode: int32(hres.GetStatus().GetCode()),
			Headers:    hdrs,
			Body:       hres.GetBody(),
		}}
	}

	return record
}
