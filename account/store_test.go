package account

import (
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestStore(t *testing.T) {
	assert.NoError(t, os.MkdirAll("data", 0744))
	store := NewStore()
	store.Set(&User{
		Email: "foo@bar.com",
	})
	assert.Len(t, store.User, 1)
	store.Set(&User{
		Email: "foo@bar.com",
	})
	assert.Len(t, store.User, 1)
	store.Set(&User{
		Email: "foo2@bar.com",
	})
	assert.Len(t, store.User, 2)
	assert.NoError(t, store.Save())
	assert.NoError(t, store.Load())
	assert.Len(t, store.User, 2)
	user := store.Get("foo@bar.com")
	assert.NotNil(t, user)
	assert.Equal(t, "foo@bar.com", user.Email)
}
