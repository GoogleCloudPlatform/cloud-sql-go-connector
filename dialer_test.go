package cloudsqlconn

import (
	"context"
	"io/ioutil"
	"net/http"
	"strings"
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

func TestDialerCanConnectToInstance(t *testing.T) {
	inst := mock.NewFakeCSQLInstance("my-project", "my-region", "my-instance")
	mc, url, cleanup := mock.HTTPClient(
		mock.InstanceGetSuccess(inst, 1),
		mock.CreateEphemeralSuccess(inst, 1),
	)
	stop := mock.StartServerProxy(mock.ServerProxyConfig{
		Response: "server-response",
		Instance: inst,
	})
	defer func() {
		stop()
		if err := cleanup(); err != nil {
			t.Fatalf("%v", err)
		}
	}()

	d, err := NewDialer(context.Background(), WithDefaultDialOptions(WithPublicIP()))
	if err != nil {
		t.Fatalf("expected NewDialer to succeed, but got error: %v", err)
	}
	replaceSQLAdminService(d, mc, url)

	conn, err := d.Dial(context.Background(), "my-project:my-region:my-instance", WithPublicIP())
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

func TestDialerInstantiationErrors(t *testing.T) {
	_, err := NewDialer(context.Background(), WithCredentialsFile("bogus-file.json"))
	if err == nil {
		t.Fatalf("expected NewDialer to return error, but got none.")
	}
}

func errorContains(err error, want string) bool {
	return strings.Contains(err.Error(), want)
}

func TestDialWithAdminAPIErrors(t *testing.T) {
	inst := mock.NewFakeCSQLInstance("my-project", "my-region", "my-instance")
	mc, url, cleanup := mock.HTTPClient()
	stop := mock.StartServerProxy(mock.ServerProxyConfig{
		Instance: inst,
	})
	defer func() {
		stop()
		_ = cleanup() // skip mock verification of HTTP methods
	}()

	d, err := NewDialer(context.Background(), WithDefaultDialOptions(WithPublicIP()))
	if err != nil {
		t.Fatalf("expected NewDialer to succeed, but got error: %v", err)
	}
	replaceSQLAdminService(d, mc, url)

	// instance name is bad
	_, err = d.Dial(context.Background(), "bad-instance-name")
	if !errorContains(err, "invalid instance") {
		t.Fatalf("expected Dial to fail with bad instance name, but it succeeded.")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// context is canceled
	_, err = d.Dial(ctx, "my-project:my-region:my-instance")
	if !errorContains(err, "context canceled") {
		t.Fatalf("expected Dial to fail with canceled context, but it succeeded.")
	}

	// failed to retrieve metadata or ephemeral cert (not registered in the mock)
	_, err = d.Dial(context.Background(), "my-project:my-region:my-instance")
	if !errorContains(err, "fetch metadata failed") {
		t.Fatalf("expected Dial to fail with missing metadata")
	}
}

func TestDialWithConfigurationErrors(t *testing.T) {
	inst := mock.NewFakeCSQLInstance("my-project", "my-region", "my-instance")
	mc, url, cleanup := mock.HTTPClient(
		mock.InstanceGetSuccess(inst, 2),
		mock.CreateEphemeralSuccess(inst, 2),
	)
	d, err := NewDialer(context.Background(), WithDefaultDialOptions(WithPublicIP()))
	if err != nil {
		t.Fatalf("expected NewDialer to succeed, but got error: %v", err)
	}
	replaceSQLAdminService(d, mc, url)

	// when failing to find private IP for public-only instance
	_, err = d.Dial(context.Background(), "my-project:my-region:my-instance", WithPrivateIP())
	if !errorContains(err, "does not have IP of type") {
		t.Fatalf("expected Dial to fail with missing metadata")
	}

	// when Dialing TCP socket fails (no server proxy running)
	_, err = d.Dial(context.Background(), "my-project:my-region:my-instance")
	if !errorContains(err, "connection refused") {
		t.Fatalf("expected Dial to fail with connection error")
	}

	stop := mock.StartServerProxy(mock.ServerProxyConfig{
		Instance:    inst,
		InvalidCert: true,
	})
	defer func() {
		stop()
		_ = cleanup() // skip mock verification of HTTP methods
	}()

	// when TLS handshake fails
	_, err = d.Dial(context.Background(), "my-project:my-region:my-instance")
	if !errorContains(err, "handshake failed") {
		t.Fatalf("expected Dial to fail with connection error")
	}
}
