//go:build linux && cgo && pam

package pamauth

/*
#cgo LDFLAGS: -l:libpam.so.0
#include <stdlib.h>
#include <string.h>

// The few declarations of <security/pam_appl.h> this file uses, so that
// building needs the PAM library and not its development package. They are
// part of the Linux-PAM ABI.
struct pam_message { int msg_style; const char *msg; };
struct pam_response { char *resp; int resp_retcode; };
struct pam_conv {
	int (*conv)(int, const struct pam_message **, struct pam_response **, void *);
	void *appdata_ptr;
};
typedef struct pam_handle pam_handle_t;

int pam_start(const char *, const char *, const struct pam_conv *, pam_handle_t **);
int pam_start_confdir(const char *, const char *, const struct pam_conv *, const char *, pam_handle_t **);
int pam_end(pam_handle_t *, int);
int pam_authenticate(pam_handle_t *, int);
int pam_acct_mgmt(pam_handle_t *, int);
int pam_setcred(pam_handle_t *, int);
int pam_open_session(pam_handle_t *, int);
int pam_close_session(pam_handle_t *, int);
int pam_set_item(pam_handle_t *, int, const void *);
int pam_get_item(const pam_handle_t *, int, const void **);
const char *pam_strerror(pam_handle_t *, int);

#define T_PAM_SUCCESS 0
#define T_PAM_BUF_ERR 5
#define T_PAM_CONV_ERR 19
#define T_PAM_PROMPT_ECHO_OFF 1
#define T_PAM_PROMPT_ECHO_ON 2

// answers is what the conversation may say: the user name for a visible
// prompt and up to two secrets for hidden prompts, in order.
struct answers {
	const char *user;
	const char *secret[2];
	int given;      // hidden prompts answered so far
	int wanted_more; // a hidden prompt came with nothing left to answer
};

static int converse(int n, const struct pam_message **msg, struct pam_response **resp, void *data) {
	struct answers *a = data;
	if (n <= 0 || n > 32)
		return T_PAM_CONV_ERR;
	struct pam_response *out = calloc(n, sizeof(*out));
	if (!out)
		return T_PAM_BUF_ERR;
	for (int i = 0; i < n; i++) {
		const char *say = NULL;
		switch (msg[i]->msg_style) {
		case T_PAM_PROMPT_ECHO_OFF:
			if (a->given < 2 && a->secret[a->given] && a->secret[a->given][0])
				say = a->secret[a->given++];
			else
				a->wanted_more = 1;
			break;
		case T_PAM_PROMPT_ECHO_ON:
			say = a->user;
			break;
		default: // information and error texts need no answer
			continue;
		}
		if (!say) {
			for (int j = 0; j < i; j++)
				free(out[j].resp);
			free(out);
			return T_PAM_CONV_ERR;
		}
		out[i].resp = strdup(say);
		if (!out[i].resp) {
			for (int j = 0; j < i; j++)
				free(out[j].resp);
			free(out);
			return T_PAM_BUF_ERR;
		}
	}
	*resp = out;
	return T_PAM_SUCCESS;
}

static int start(const char *service, const char *confdir, const char *user, struct answers *a, pam_handle_t **h) {
	struct pam_conv conv = { converse, a };
	if (confdir && confdir[0])
		return pam_start_confdir(service, user, &conv, confdir, h);
	return pam_start(service, user, &conv, h);
}

static void wipe(char *s) {
	if (s)
		memset(s, 0, strlen(s));
}
*/
import "C"

import (
	"runtime"
	"unsafe"
)

const available = true

// Values of <security/_pam_types.h>.
const (
	pamSuccess          = 0
	pamNewAuthtokReqd   = 12
	pamAcctExpired      = 13
	pamPermDenied       = 6
	pamUser             = 2
	pamRHost            = 4
	pamEstablishCred    = 0x2
	pamDeleteCred       = 0x4
	pamDisallowNullAuth = 0x1
)

func authenticate(req Request) (string, error) {
	// A PAM transaction belongs to the thread that started it.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cs := func(s string) *C.char { return C.CString(s) }
	service, confdir, name := cs(req.Service), cs(req.ConfDir), cs(req.User)
	password, code := cs(req.Password), cs(req.Code)
	defer func() {
		// The secrets do not outlive the attempt.
		C.wipe(password)
		C.wipe(code)
		for _, p := range []*C.char{service, confdir, name, password, code} {
			C.free(unsafe.Pointer(p))
		}
	}()
	ans := (*C.struct_answers)(C.calloc(1, C.sizeof_struct_answers))
	defer C.free(unsafe.Pointer(ans))
	ans.user = name
	ans.secret[0], ans.secret[1] = password, code

	var h *C.pam_handle_t
	if rc := C.start(service, confdir, name, ans, &h); rc != pamSuccess {
		return "", ErrDenied
	}
	rc := C.int(pamSuccess)
	defer func() { C.pam_end(h, rc) }()
	if req.RemoteHost != "" {
		rhost := cs(req.RemoteHost)
		defer C.free(unsafe.Pointer(rhost))
		C.pam_set_item(h, pamRHost, unsafe.Pointer(rhost))
	}

	if rc = C.pam_authenticate(h, pamDisallowNullAuth); rc != pamSuccess {
		// The password was taken and a further hidden prompt followed.
		if ans.wanted_more != 0 && ans.given >= 1 && req.Code == "" {
			return "", ErrNeedCode
		}
		return "", ErrDenied
	}
	// The account phase: is this account allowed to log in now?
	if rc = C.pam_acct_mgmt(h, pamDisallowNullAuth); rc != pamSuccess {
		reason := C.GoString(C.pam_strerror(h, rc))
		switch rc {
		case pamNewAuthtokReqd:
			reason = "the password has expired and must be changed on the host"
		case pamAcctExpired:
			reason = "the account has expired"
		case pamPermDenied:
			reason = "the account is locked or not permitted"
		}
		return "", &AccountError{Reason: reason}
	}
	// Credentials and session, opened and closed at once: nothing here
	// keeps a login session, but the modules get to record and limit it.
	// Whether credentials could be established does not decide the login:
	// this program uses none, and a stack whose modules have nothing to
	// set reports that as a failure.
	C.pam_setcred(h, pamEstablishCred)
	if rc = C.pam_open_session(h, 0); rc != pamSuccess {
		C.pam_setcred(h, pamDeleteCred)
		return "", &AccountError{Reason: C.GoString(C.pam_strerror(h, rc))}
	}
	C.pam_close_session(h, 0)
	C.pam_setcred(h, pamDeleteCred)
	rc = pamSuccess

	// A module may have mapped the name (an alias, a different case).
	var item unsafe.Pointer
	if C.pam_get_item(h, pamUser, &item) == pamSuccess && item != nil {
		return C.GoString((*C.char)(item)), nil
	}
	return req.User, nil
}
