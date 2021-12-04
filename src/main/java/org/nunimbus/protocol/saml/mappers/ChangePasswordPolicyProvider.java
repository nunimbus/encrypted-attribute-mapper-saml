package org.nunimbus.protocol.saml.mappers;

import org.keycloak.models.KeycloakContext;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.policy.PasswordPolicyProvider;
import org.keycloak.policy.PolicyError;
import org.jboss.resteasy.spi.HttpRequest;

public class ChangePasswordPolicyProvider implements PasswordPolicyProvider {

    private static final String ERROR_MESSAGE = "Error: User has password-encrypted attributes. Cannot reset password.";

    private KeycloakContext context;
    private UserModel user;
    private Boolean error = false;

    public ChangePasswordPolicyProvider(KeycloakContext context) {
        this.context = context;
    }

    @Override
    public PolicyError validate(String username, String password) {
    	if (user == null) {
    		return null;
    	}

    	HttpRequest request = context.getContextObject(HttpRequest.class);
    	
    	if (request.getUri().getPathSegments().get(0).getPath().equals("admin")) {
    		context.getRealm().getClientsStream().forEach(client-> {
    			client.getProtocolMappersStream().forEach(mapper->{
    				if (mapper.getProtocolMapper().equals("saml-password-encrypted-user-attribute-mapper")) {
    					mapper.getConfig().forEach((K, V) -> {
    						if (K.equals("user.attribute")) {
    							if (user.getAttributeStream(V).count() > 0) {
    								error = true;
    							}
    						}
    					});
    				}
    			});
    		});

    		if (error) {
    			return new PolicyError(ERROR_MESSAGE);
    		}
    	}
    	else {
/*
	    	String execution = request.getUri().getQueryParameters().get("execution").get(0);
	    	String client_id = request.getUri().getQueryParameters().get("client_id").get(0);
	
			context.getRealm().getClientsStream().forEach(client-> {
				client.getProtocolMappersStream().forEach(mapper->{
					if (mapper.getProtocolMapper().equals("saml-password-encrypted-user-attribute-mapper")) {
						mapper.getConfig().forEach((K, V) -> {
							if (K.equals("user.attribute")) {
								long attributes = user.getAttributeStream(V).count();
								
								if (attributes > 0 && execution.equals("UPDATE_PASSWORD") && client_id.equals("account-console")) {
									int k = 1;
								}
								int j = 1;
							}
						});
						int i = 1;
					}
				});
			});
*/		
			// Required to be here to pass the password to the SAML mappers during registration
			context.getAuthenticationSession().setAuthNote("password", password);
    	}
    	
        return null;
    }

    @Override
    public PolicyError validate(RealmModel realm, UserModel user, String password) {
    	this.user = user;
        return validate(user.getUsername(), password);
    }

    @Override
    public Object parseConfig(String value) {
        return null;
    }

    @Override
    public void close() {
    }
}
