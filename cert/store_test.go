package cert

import (
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestStore(t *testing.T) {
	assert.NoError(t, os.RemoveAll("data"))
	assert.NoError(t, os.MkdirAll("data", 0744))
	store := newStore()
	assert.NoError(t, store.backup())
	store.set(&Cert{
		Hetzner: Hetzner{
			Name: "foo",
		},
	})
	assert.Len(t, store.Certs, 1)
	store.set(&Cert{
		Hetzner: Hetzner{
			Name: "foo",
		},
	})
	assert.Len(t, store.Certs, 1)
	store.set(&Cert{
		Hetzner: Hetzner{
			Name: "bar",
		},
	})
	assert.Len(t, store.Certs, 2)
	assert.NoError(t, store.save())
	assert.NoError(t, store.load())
	assert.Len(t, store.Certs, 2)
	cert := store.get(CertRequest{
		Hetzner: Hetzner{
			Name: "foo",
		},
	})
	assert.NotNil(t, cert)
	assert.Equal(t, "foo", cert.Hetzner.Name)
	assert.NoError(t, store.backup())
	assert.FileExists(t, certsBackupFile)
}
