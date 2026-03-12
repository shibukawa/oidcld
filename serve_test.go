package main

import (
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/shibukawa/oidcld/internal/config"
)

func TestResolveServePort(t *testing.T) {
	assert.Equal(t, "19000", resolveServePort("19000", false))
	assert.Equal(t, config.DefaultHTTPPort, resolveServePort("", false))
	assert.Equal(t, config.DefaultHTTPSPort, resolveServePort("", true))
}

func TestResolveHTTPReadOnlyPort(t *testing.T) {
	t.Run("disabled without HTTPS", func(t *testing.T) {
		assert.Equal(t, "", resolveHTTPReadOnlyPort("19080", config.DefaultHTTPPort, false))
	})

	t.Run("uses CLI override", func(t *testing.T) {
		assert.Equal(t, "19080", resolveHTTPReadOnlyPort("19080", config.DefaultHTTPSPort, true))
	})

	t.Run("accepts disabled sentinel", func(t *testing.T) {
		assert.Equal(t, "", resolveHTTPReadOnlyPort("off", config.DefaultHTTPSPort, true))
	})

	t.Run("uses default companion port in HTTPS mode", func(t *testing.T) {
		assert.Equal(t, defaultHTTPSReadOnlyPort, resolveHTTPReadOnlyPort("", config.DefaultHTTPSPort, true))
	})

	t.Run("suppresses default companion when ports collide", func(t *testing.T) {
		assert.Equal(t, "", resolveHTTPReadOnlyPort("", defaultHTTPSReadOnlyPort, true))
	})
}
