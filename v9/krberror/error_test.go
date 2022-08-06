package krberror

import (
	"errors"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKrberrorImplement(t *testing.T) {
	i := new(KRBError)
	f := "testing %s %s"
	s := "hello world"

	assert.Implements(t, i, EncodingErrorf(f, s, s))
	assert.Implements(t, i, NetworkingErrorf(f, s, s))
	assert.Implements(t, i, DecryptingErrorf(f, s, s))
	assert.Implements(t, i, EncryptingErrorf(f, s, s))
	assert.Implements(t, i, ChksumErrorf(f, s, s))
	assert.Implements(t, i, KRBMsgErrorf(f, s, s))
	assert.Implements(t, i, ConfigErrorf(f, s, s))
	assert.Implements(t, i, KDCErrorf(f, s, s))
}

func TestKrberrorWrap(t *testing.T) {
	t.Parallel()
	err := errors.New("0")
	kerr := Errorf(err, NetworkingErrorf, "krberr %s", "1")
	kerr = Errorf(kerr, KDCErrorf, "krberr %s", "2")
	assert.Equal(t, "[Root cause: Networking_Error] krberr 2 < krberr 1 < 0", kerr.Error())
}

func TestKrberrorAs(t *testing.T) {
	err, errorFormat := wrappedErr()

	for target, s := range errorFormat {
		s = "krberr " + s
		switch target.(type) {
		case *EncodingError:
			krberr := new(EncodingError)
			krberr.KRBError = &krberror{}
			errors.As(err, krberr)
			assert.Equal(t, s, krberr.String())
		case *NetworkingError:
			krberr := new(NetworkingError)
			krberr.KRBError = &krberror{}
			errors.As(err, krberr)
			assert.Equal(t, s, krberr.String())
		case *DecryptingError:
			krberr := new(DecryptingError)
			krberr.KRBError = &krberror{}
			errors.As(err, krberr)
			assert.Equal(t, s, krberr.String())
		case *EncryptingError:
			krberr := new(EncryptingError)
			krberr.KRBError = &krberror{}
			errors.As(err, krberr)
			assert.Equal(t, s, krberr.String())
		case *ChksumError:
			krberr := new(ChksumError)
			krberr.KRBError = &krberror{}
			errors.As(err, krberr)
			assert.Equal(t, s, krberr.String())
		case *KRBMsgError:
			krberr := new(KRBMsgError)
			krberr.KRBError = &krberror{}
			errors.As(err, krberr)
			assert.Equal(t, s, krberr.String())
		case *ConfigError:
			krberr := new(ConfigError)
			krberr.KRBError = &krberror{}
			errors.As(err, krberr)
			assert.Equal(t, s, krberr.String())
		case *KDCError:
			krberr := new(KDCError)
			krberr.KRBError = &krberror{}
			errors.As(err, krberr)
			assert.Equal(t, s, krberr.String())
		}
	}
}

func TestKrberrorIs(t *testing.T) {
	err, errorFormat := wrappedErr()

	for target := range errorFormat {
		assert.True(t, errors.Is(err, target))
	}
}

func wrappedErr() (error, map[KRBError]string) {
	var errs = []func(format string, a ...interface{}) KRBError{
		EncodingErrorf,
		NetworkingErrorf,
		DecryptingErrorf,
		EncryptingErrorf,
		ChksumErrorf,
		KRBMsgErrorf,
		ConfigErrorf,
		KDCErrorf,
	}
	var errorFormat = make(map[KRBError]string)
	err := errors.New("0")
	for i, c := range errs {
		err = Errorf(err, c, "krberr %s", strconv.Itoa(i+1))
		errorFormat[err.(KRBError)] = strconv.Itoa(i + 1)
	}
	return err, errorFormat
}
