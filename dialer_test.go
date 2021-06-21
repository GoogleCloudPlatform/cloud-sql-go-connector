package cloudsqlconn

import (
	"context"
	"io/ioutil"
	"net/http"
	"testing"

	"cloud.google.com/cloudsqlconn/internal/mock"
	"google.golang.org/api/option"
	sqladmin "google.golang.org/api/sqladmin/v1beta4"
)

// replaceSQLAdminClient patches the Dialer's SQL Admin API client with one that
// uses the provided HTTP client and endpoint.
func replaceSQLAdminService(d *Dialer, client *http.Client, endpoint string) {
	svc, err := sqladmin.NewService(
		context.Background(),
		option.WithHTTPClient(client),
		option.WithEndpoint(endpoint),
	)
	if err != nil {
		panic(err)
	}
	d.sqladmin = svc
}

func TestDialer(t *testing.T) {
	inst := mock.NewFakeCSQLInstance("my-project", "my-region", "my-instance")
	mc, url, cleanup := mock.HTTPClient(
		mock.InstanceGetSuccess(inst, 1),
		mock.CreateEphemeralSuccess(inst, 1),
	)
	stop := mock.StartServerProxy(serverProxyPort, "server-response", inst)
	defer func() {
		stop()
		if err := cleanup(); err != nil {
			t.Fatalf("%v", err)
		}
	}()

	d, err := NewDialer(context.Background())
	if err != nil {
		t.Fatalf("expected NewDialer to succeed, but got error: %v", err)
	}
	replaceSQLAdminService(d, mc, url)

	conn, err := d.Dial(context.Background(), "my-project:my-region:my-instance")
	if err != nil {
		t.Fatalf("expected Dial to succeed, but got error: %v", err)
	}
	defer conn.Close()

	data, err := ioutil.ReadAll(conn)
	if err != nil {
		t.Fatalf("expected ReadAll to succeed, got error %v", err)
	}
	if string(data) != "server-response" {
		t.Fatalf("expected known response from the server, but got %v", string(data))
	}
}
