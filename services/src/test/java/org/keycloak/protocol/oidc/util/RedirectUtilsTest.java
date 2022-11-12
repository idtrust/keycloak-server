package org.keycloak.protocol.oidc.util;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.HashSet;
import java.util.Set;
import org.junit.Assert;
import org.junit.Test;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.utils.RedirectUtils;

public class RedirectUtilsTest {

  @Test
  public void test_valid_redirects() {

    KeycloakSession session = mock(KeycloakSession.class);
    KeycloakContext kctx = mock(KeycloakContext.class);

    when(session.getContext()).thenReturn(kctx);

    Set<String> redirects = new HashSet<>();
    redirects.add("https://example.com/*");
    redirects.add("https://example2.com/abc");
    redirects.add("https://[a-z][a-z-]+\\.example\\.com/*");

    String result = RedirectUtils.verifyRedirectUri(session, "https://example.com",
        "https://example.com/abc/def",
        redirects, true);
    Assert.assertEquals("https://example.com/abc/def", result);

    result = RedirectUtils.verifyRedirectUri(session, "https://example.com",
        "https://example.com/fgh",
        redirects, true);
    Assert.assertEquals("https://example.com/fgh", result);

    result = RedirectUtils.verifyRedirectUri(session, "https://example2.com",
        "https://example2.com/abc",
        redirects, true);
    Assert.assertEquals("https://example2.com/abc", result);

    result = RedirectUtils.verifyRedirectUri(session, "https://example2.com",
        "https://example2.com/fgh",
        redirects, true);
    Assert.assertNull(result);

    result = RedirectUtils.verifyRedirectUri(session, "https://example.com",
        "https://subdomain.example.com/fgh",
        redirects, true);
    Assert.assertEquals("https://subdomain.example.com/fgh", result);

    result = RedirectUtils.verifyRedirectUri(session, "https://example.com",
        "https://sub-domain.example.com/fgh",
        redirects, true);
    Assert.assertEquals("https://sub-domain.example.com/fgh", result);

  }

}
