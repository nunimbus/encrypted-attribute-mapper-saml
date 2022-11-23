package org.nunimbus.protocol.saml.mappers;

/**
 * When the user changes their password, the encrypted and password-encrypted
 * user attributes need to be updated accordingly.
 * 
 * To enable:
 * - Events > Config (tab)
 * - Add "pw-change-update-encrypted-user-attributes"
 *
 * @author Andrew Summers
 * @version $Revision: 1 $
 */
import java.util.stream.Stream;
import org.keycloak.credential.CredentialModel;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.jboss.resteasy.spi.HttpRequest;

import util.CryptoUtils;
import util.StreamsForEach;

public class SimpleEventListenerProvider implements EventListenerProvider {

    private final KeycloakSession session;
    private final RealmModel realm;

    public SimpleEventListenerProvider(KeycloakSession session) {
        this.session = session;
        this.realm = this.session.getContext().getRealm();
    }

    // Update saml-password-encrypted-user-attribute-mapper attributes according to user's new password
    @Override
    public void onEvent(Event event) {
//    	if (session.getContext().getContextObject(HttpRequest.class).getDecodedFormParameters().get("password") != null) {
//    		session.getContext().getAuthenticationSession().setAuthNote("password", session.getContext().getContextObject(HttpRequest.class).getDecodedFormParameters().get("password").get(0));
//    	}
    	
/*    	if (event.getType().name().equals("LOGIN") && event.getClientId().equals("account-console")) {
    		if (session.getContext().getContextObject(HttpRequest.class).getDecodedFormParameters().get("password") != null) {
    		String username = session.getContext().getContextObject(HttpRequest.class).getDecodedFormParameters().get("username").get(0);
    		String password = session.getContext().getContextObject(HttpRequest.class).getDecodedFormParameters().get("password").get(0);
    		UserModel user = session.users().getUserByUsername(realm, username);
    		String currentCredential = session.userCredentialManager().getStoredCredentialsStream(realm, user).sorted(CredentialModel.comparingByStartDateDesc()).findFirst().get().getValue();

    		// Loop through each client's mappers, find the encrypted user attribute mappers, and update the values according to the new password credential.
    		realm.getClientsStream().forEach(client-> {
    			client.getProtocolMappersStream().forEach(mapper->{
    				if (mapper.getProtocolMapper().equals("saml-password-encrypted-user-attribute-mapper")) {
    					mapper.getConfig().forEach((K, V) -> {
    						if (K.equals("user.attribute")) {
    							user.getAttributeStream(V).forEach(encrypted-> {
//									try {
//										String decrypted = CryptoUtils.decrypt(encrypted, password);
										
//										String encryptedCookie = CryptoUtils.encrypt(decrypted, currentCredential);
//								    	CookieHelper.addCookie(V, encryptedCookie, "/auth/realms/" + event.getRealmId(), null, null, -1, true, true);

//								    	System.err.println("LOGIN: Setting cookies for password-encrypted values:");
//    									System.err.println(new Throwable().getStackTrace()[0].getFileName() + ":" + new Throwable().getStackTrace()[0].getLineNumber());
//										System.err.println("Encrypted:  " + encryptedCookie.substring(0, 8).substring(0, 8));
//										System.err.println("Credential: " + currentCredential.substring(0, 8).substring(0, 8));
//										System.err.println("Password:   " + password);
//										System.err.println("Key:        " + decrypted.substring(0, 8).substring(0, 8));
//										System.err.println();
//										System.err.println();
//									} catch (Exception e) {
//										System.err.println("ERROR: " + new Throwable().getStackTrace()[0].getFileName() + ":" + new Throwable().getStackTrace()[0].getLineNumber());
//										//e.printStackTrace();
//									}
    							});
    						}
    					});
    				}
    			});
    		});
    		}
    	}
  */  	
    	if (event.getType().name().equals("UPDATE_PASSWORD") && event.getClientId().equals("account-console")) {
    		String username = session.getContext().getContextObject(HttpRequest.class).getDecodedFormParameters().get("username").get(0);
    		UserModel user = session.users().getUserByUsername(realm, username);
    		String password = session.getContext().getContextObject(HttpRequest.class).getDecodedFormParameters().get("password").get(0);
    		String password_new = session.getContext().getContextObject(HttpRequest.class).getDecodedFormParameters().get("password-new").get(0);
    		Stream<CredentialModel> credentials = session.userCredentialManager().getStoredCredentialsStream(realm, user).sorted(CredentialModel.comparingByStartDateDesc());;
    		String currentCredential = session.userCredentialManager().getStoredCredentialsStream(realm, user).sorted(CredentialModel.comparingByStartDateDesc()).findFirst().get().getValue();

    		// Loop through each client's mappers, find the encrypted user attribute mappers, and update the values according to the new password credential.
    		this.session.getContext().getRealm().getClientsStream().forEach(client-> {
    			client.getProtocolMappersStream().forEach(mapper->{
    				if (mapper.getProtocolMapper().equals("saml-password-encrypted-user-attribute-mapper")) {
    					mapper.getConfig().forEach((K, V) -> {
    						if (K.equals("user.attribute")) {
    							user.getAttributeStream(V).forEach(encrypted-> {
									try {
										String decrypted = CryptoUtils.decrypt(encrypted, password);
										
										int pwHistory = Integer.parseInt(session.getContext().getRealm().getPasswordPolicy().getPolicyConfig("passwordHistory").toString());
										
										for (int i = pwHistory; i > 0; i--) {
//											if (! user.getAttributeStream(V + "-old-" + String.valueOf(i - 1)).findFirst().isEmpty()) {
											if (user.getAttributeStream(V + "-old-" + String.valueOf(i - 1)).findFirst().isPresent()) {
												user.setSingleAttribute(V + "-old-" + String.valueOf(i), user.getAttributeStream(V + "-old-" + String.valueOf(i - 1)).findFirst().get());
											}
										}

										user.setSingleAttribute(V + "-old-1", user.getAttributeStream(V).findFirst().get());
										user.setSingleAttribute(V, CryptoUtils.encrypt(decrypted, password_new));

/*
								    	System.err.println("PW CHANGE: Password-encrypted values:");
								    	System.err.println(new Throwable().getStackTrace()[0].getFileName() + ":" + new Throwable().getStackTrace()[0].getLineNumber());
										System.err.println("Credential:   " + currentCredential.substring(0, 8));
										System.err.println("Password:     " + password);
										System.err.println("New Password: " + password_new);
										System.err.println("Key:          " + decrypted.substring(0, 8));
										System.err.println();
										System.err.println();
/**/
									} catch (Exception e) {
										System.err.println("ERROR: " + new Throwable().getStackTrace()[0].getFileName() + ":" + new Throwable().getStackTrace()[0].getLineNumber());
										//e.printStackTrace();
									}
    							});
    						}
    					});
    				}
    				// There's a problem, here
    				else if (mapper.getProtocolMapper().equals("saml-encrypted-user-attribute-mapper")) {
    					mapper.getConfig().forEach((K, V) -> {
    						if (K.equals("user.attribute")) {
    							user.getAttributeStream(V).forEach(encrypted-> {
    								StreamsForEach.forEach(credentials, (credential, breaker) -> {
    									if (! credential.getValue().equals(currentCredential)) {
	    									try {
	    										String decrypted = CryptoUtils.decrypt(encrypted, credential.getValue());

	    										int pwHistory = Integer.parseInt(session.getContext().getRealm().getPasswordPolicy().getPolicyConfig("passwordHistory").toString());
	    										
	    										for (int i = pwHistory; i > 0; i--) {
//	    											if (! user.getAttributeStream(V + "-old-" + String.valueOf(i - 1)).findFirst().isEmpty()) {
	    											if (user.getAttributeStream(V + "-old-" + String.valueOf(i - 1)).findFirst().isPresent()) {
	    												user.setSingleAttribute(V + "-old-" + String.valueOf(i), user.getAttributeStream(V + "-old-" + String.valueOf(i - 1)).findFirst().get());
	    											}
	    										}

	    										user.setSingleAttribute(V + "-old-1", user.getAttributeStream(V).findFirst().get());
	    										user.setSingleAttribute(V, CryptoUtils.encrypt(decrypted, password_new));
	    										
/*
	    										System.err.println("PW CHANGE: Encrypted values:");
	    								    	System.err.println(new Throwable().getStackTrace()[0].getFileName() + ":" + new Throwable().getStackTrace()[0].getLineNumber());
	    										System.err.println("Credential:   " + currentCredential.substring(0, 8));
	    										System.err.println("Password:     " + password);
	    										System.err.println("New Password: " + password_new);
	    										System.err.println("Key:          " + decrypted.substring(0, 8));
	    										System.err.println();
	    										System.err.println();
/**/

	    										breaker.stop();
	    									} catch (Exception e) {
	    										System.err.println("ERROR: " + new Throwable().getStackTrace()[0].getFileName() + ":" + new Throwable().getStackTrace()[0].getLineNumber());
	    										//e.printStackTrace();
	    									}
    									}
    								});
    							});
    						}
    					});
    				}
    			});
    		});
    	}
    }

    // Set a password validator to trigger when passwords are changed/set
    // The event handler checks to see if the password was successfully updated and decrypts/reencrypts the encryption key attribute accordingly
    @Override
    public void onEvent(AdminEvent event, boolean includeRepresentation) {
    	if (event.getResourcePath() != null) {
	    	String[] resource = event.getResourcePath().split("/");
	
	    	// This fails. For some reason, getUserById won't work.
/*	    	if (resource.length == 3 && resource[0].equals("users") && resource[2].equals("reset-password")) {
	    		UserModel user = session.users().getUserById(realm, resource[1]);
	    		Stream<CredentialModel> credentials = session.userCredentialManager().getStoredCredentialsStream(realm, user).sorted(CredentialModel.comparingByStartDateDesc());;
	    		String currentCredential = session.userCredentialManager().getStoredCredentialsStream(realm, user).sorted(CredentialModel.comparingByStartDateDesc()).findFirst().get().getValue();

	    		// Loop through each client's mappers, find the encrypted user attribute mappers, and update the values according to the new password credential.
	    		realm.getClientsStream().forEach(client-> {
	    			client.getProtocolMappersStream().forEach(mapper->{
	    				if (mapper.getProtocolMapper().equals("saml-encrypted-user-attribute-mapper")) {
	    					mapper.getConfig().forEach((K, V) -> {
	    						if (K.equals("user.attribute")) {
	    							user.getAttributeStream(V).forEach(encrypted-> {
	    								StreamsForEach.forEach(credentials, (credential, breaker) -> {
	    									if (! credential.getValue().equals(currentCredential)) {
		    									try {
		    										String decrypted = CryptoUtils.decrypt(encrypted, credential.getValue());
		    										user.setSingleAttribute(V, CryptoUtils.encrypt(decrypted, currentCredential));
		    										breaker.stop();
		    									} catch (Exception e) {
		    										System.err.println("ERROR: " + new Throwable().getStackTrace()[0].getFileName() + ":" + new Throwable().getStackTrace()[0].getLineNumber());
		    										//e.printStackTrace();
		    									}
	    									}
	    								});
	    							});
	    						}
	    					});
	    				}
	    			});
	    		});
	    	}
*/
	    }
    }

    @Override
    public void close() {
    }
}
