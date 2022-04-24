package org.nunimbus.protocol.saml.mappers;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
* On login, this makes the user's password accessible as a Keycloak session auth
* note for other parts of the authentication flow.
* 
* To enable:
* - Authentication > Flows
* - Create a copy of the Browser flow
* - Under the "Browser Forms" Auth Type, click Actions > Add execution
* - Select "Form Parameter Authenticator"
*
* @author Andrew Summers
* @version $Revision: 1 $
*/
public class FormParameterAuthenticator implements Authenticator {

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
		String password = context.getHttpRequest().getDecodedFormParameters().get("password").get(0);
		
		// This makes the password available to downstream parts of the flow.
		context.getAuthenticationSession().setAuthNote("password", password);
		context.success();
    }

    @Override
    public void action(AuthenticationFlowContext context) {
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }
}
