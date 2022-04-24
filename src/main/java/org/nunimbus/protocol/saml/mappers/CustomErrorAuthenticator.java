package org.nunimbus.protocol.saml.mappers;

import org.jboss.resteasy.spi.HttpRequest;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.util.CookieHelper;
import org.keycloak.sessions.AuthenticationSessionModel;

import util.CryptoUtils;

/**
* Passes the password to the SAML mappers during login; for example:
* - UserEncryptedAttributeStatementMapper
* - UserPasswordEncryptedAttributeStatementMapper
* 
* @author Andrew Summers
* @version $Revision: 1 $
*/
public class CustomErrorAuthenticator implements Authenticator {

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
		String username = context.getHttpRequest().getDecodedFormParameters().get("username").get(0);
		String password = context.getHttpRequest().getDecodedFormParameters().get("password").get(0);
		
		// Required to be here to pass the password to the SAML mappers during login
		context.getAuthenticationSession().setAuthNote("password", password);
		context.success();
    }

    @Override
    public void action(AuthenticationFlowContext context) {
    	int i = 1;
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
