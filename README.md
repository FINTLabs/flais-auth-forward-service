# FLAIS AuthForward Service

[![CI](https://github.com/FINTLabs/flais-auth-forward-service/actions/workflows/CI.yaml/badge.svg)](https://github.com/FINTLabs/flais-auth-forward-service/actions/workflows/CI.yaml)

This is an implementation of
the [Træfik forward auth middleware](https://doc.traefik.io/traefik/middlewares/http/forwardauth/).

# Local development

When testing the application on your local machine you need to make use
of [Chrome modheader](https://chrome.google.com/webstore/detail/modheader-modify-http-hea/idgpnmonknjnojddfkpgkljpfnnfcklj)
or a similar tool. The following headers need to be set:

| Header              | Value       |
|---------------------|-------------|
| `X-Forwarded-Host`  | `localhost` |
| `X-Forwarded-Proto` | `http`      |
| `X-Forwarded-Port`  | 8080        |

# Properties

| Property                              | Default                                         | Description                                                                                 |
|---------------------------------------|-------------------------------------------------|---------------------------------------------------------------------------------------------|
| fint.sso.client-id                    |                                                 | Client id of the OAuth client                                                               |
| fint.sso.client-secret                |                                                 | Client secret of the OAuth client                                                           |
| fint.sso.issuer-uri                   | `https://idp.felleskomponent.no/nidp/oauth/nam` | The IDP uri.                                                                                |
| fint.sso.scopes                       | `end-user-profile` and `openid`                 | Scopes                                                                                      |
| fint.sso.session-max-age-in-minutes   | 1440                                            | This cannot be set to more than the refresh token timeout value of the IDP                  |
| fint.sso.enforce-https                | `true`                                          | This is used in a local development setting where you need to run the application in `http` |
| fint.sso.redirect-after-logout-uri    | `/_oauth/logged-out`                            | This is the url to send the user to after logout.                                           |
| fint.sso.redirect-after-login-uri     | `/`                                             | This is the url to send the user to after login.                                            |
| fint.sso.logout-message               | Du er logget ut.                                | The message to show on the default logout page.                                             |
| fint.sso.verify-token-signature       | `true`                                          | Whether we should verify the token signature or not.                                        |
| fint.sso.seconds-before-token-refresh | 60                                              | How near token expiration time we should refresh the token in seconds.                      |
| spring.webflux.base-path              | `/`                                             | Base path of the application.                                                               |
| fint.sso.old-sessions-cleanup-cron    | `0 */1 * * * *`                                 | Cron expression for how often we should remove non-active sessions.                         |
| fint.sso.token-refresh-cron           | `0 */1 * * * *`                                 | Cron expression for how often we should check and refresh tokens.                           |
