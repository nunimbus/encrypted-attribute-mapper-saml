package org.nunimbus.protocol.saml.mappers;

import org.keycloak.credential.CredentialModel;
import org.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.ProtocolMapperUtils;
import org.keycloak.protocol.saml.mappers.AbstractSAMLProtocolMapper;
import org.keycloak.protocol.saml.mappers.AttributeStatementHelper;
import org.keycloak.protocol.saml.mappers.SAMLAttributeStatementMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.util.CookieHelper;

import util.CryptoUtils;
import util.StreamsForEach;

import org.keycloak.common.util.ServerCookie;
import org.jboss.resteasy.spi.HttpRequest;
import org.jboss.resteasy.spi.HttpResponse;
import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.HttpHeaders;

import java.util.Collection;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

/**
 * Mappings UserModel attribute (not property name of a getter method) to an AttributeStatement.
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class UserPasswordEncryptedAttributeStatementMapper extends AbstractSAMLProtocolMapper implements SAMLAttributeStatementMapper {
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();

    static {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName(ProtocolMapperUtils.USER_ATTRIBUTE);
        property.setLabel(ProtocolMapperUtils.USER_MODEL_ATTRIBUTE_LABEL);
        property.setHelpText(ProtocolMapperUtils.USER_MODEL_ATTRIBUTE_HELP_TEXT);
        configProperties.add(property);
        AttributeStatementHelper.setConfigProperties(configProperties);

        property = new ProviderConfigProperty();
        property.setName(ProtocolMapperUtils.AGGREGATE_ATTRS);
        property.setLabel(ProtocolMapperUtils.AGGREGATE_ATTRS_LABEL);
        property.setHelpText(ProtocolMapperUtils.AGGREGATE_ATTRS_HELP_TEXT);
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        configProperties.add(property);
    }

    public static final String PROVIDER_ID = "saml-password-encrypted-user-attribute-mapper";


    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }
    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Password Encrypted User Attribute";
    }

    @Override
    public String getDisplayCategory() {
        return AttributeStatementHelper.ATTRIBUTE_STATEMENT_CATEGORY;
    }

    @Override
    public String getHelpText() {
        return "Map a custom user attribute encrypted by the user's password to a to a SAML attribute.";
    }

    @Override
    public void transformAttributeStatement(AttributeStatementType attributeStatement, ProtocolMapperModel mappingModel, KeycloakSession session, UserSessionModel userSession, AuthenticatedClientSessionModel clientSession) {
    	UserModel user = userSession.getUser();
        String attributeName = mappingModel.getConfig().get(ProtocolMapperUtils.USER_ATTRIBUTE);
        boolean aggregateAttrs = Boolean.valueOf(mappingModel.getConfig().get(ProtocolMapperUtils.AGGREGATE_ATTRS));
        Collection<String> attributeValues = KeycloakModelUtils.resolveAttribute(user, attributeName, aggregateAttrs);
        if (attributeValues.isEmpty()) return;

        RealmModel realm = userSession.getRealm();
    	HttpRequest request = session.getContext().getContextObject(HttpRequest.class);

    	// Deprecated. Recommended to use PasswordCredentialModel.getSecretData().getValue() or OTPCredentialModel.getSecretData().getValue()
        String currentCredential = session.userCredentialManager().getStoredCredentialsStream(realm, user).sorted(CredentialModel.comparingByStartDateDesc()).findFirst().get().getValue();

    	// On login, the cookie may not be set. Check for the existence of the password in the HTTP form data
        if (session.getContext().getAuthenticationSession().getAuthNote("password") != null) {
            String encrypted = attributeValues.toArray()[0].toString();
	        try {
	        	String password = session.getContext().getAuthenticationSession().getAuthNote("password");
				String key = CryptoUtils.decrypt(encrypted, password);

				String encryptedNew = CryptoUtils.encrypt(key, password);
				user.setSingleAttribute(attributeName, encryptedNew);					

				System.err.println("Mapping pw-encrypted attribute");
		    	System.err.println(new Throwable().getStackTrace()[0].getFileName() + ":" + new Throwable().getStackTrace()[0].getLineNumber());
				System.err.println("Encrypted: " + encrypted.substring(0, 8));
				System.err.println("Password:  " + password);
				System.err.println("Key:       " + key.substring(0, 8));
				System.err.println();
				System.err.println();
				
//				String encryptedCookie = CryptoUtils.encrypt(key, currentCredential);
//		    	CookieHelper.addCookie(attributeName, encryptedCookie, "/auth/realms/nunimbus"/* + event.getRealmId()*/, null, null, -1, true, true);

				attributeValues.clear();
				attributeValues.add(key);
			} catch (Exception e) {
				System.err.println("ERROR: " + new Throwable().getStackTrace()[0].getFileName() + ":" + new Throwable().getStackTrace()[0].getLineNumber());
				//e.printStackTrace();
			}
        }
        else {
    		String cookie = request.getHttpHeaders().getCookies().get(attributeName).getValue();
    		//String cookie = CookieHelper.getCookieValue(attributeName).toArray()[0];

	        Stream<CredentialModel> credentials = session.userCredentialManager().getStoredCredentialsStream(realm, user).sorted(CredentialModel.comparingByStartDateDesc());
	
	        // Loop through all credentials in the user's history and try to decrypt the secret. Then, re-encrypt the secret with the current credential.
	        StreamsForEach.forEach(credentials, (c, breaker) -> {
		        try {
		        	String credential = c.getValue();
					String key = CryptoUtils.decrypt(cookie, credential);
	
					String encryptedNew = CryptoUtils.encrypt(key, credential);
					user.setSingleAttribute(attributeName, encryptedNew);					

					System.err.println("Mapping pw-encrypted attribute");
			    	System.err.println(new Throwable().getStackTrace()[0].getFileName() + ":" + new Throwable().getStackTrace()[0].getLineNumber());
					System.err.println("Encrypted:   " + cookie.substring(0, 8));
					System.err.println("Credential:  " + credential.substring(0, 8));
					System.err.println("Key:         " + key.substring(0, 8));
					System.err.println();
					System.err.println();
	
//					if (! currentCredential.equals(credential)) {
//						String encryptedCookie = CryptoUtils.encrypt(key, currentCredential);
//				    	CookieHelper.addCookie(attributeName, encryptedCookie, "/auth/realms/nunimbus"/* + event.getRealmId()*/, null, null, -1, true, true);
//					}
					
					attributeValues.clear();
					attributeValues.add(key);
					breaker.stop();
				} catch (Exception e) {
					System.err.println("ERROR: Couldn't decrypt password-encrypted attribute " + new Throwable().getStackTrace()[0].getFileName());
					//e.printStackTrace();
				}
			});
        }

        AttributeStatementHelper.addAttributes(attributeStatement, mappingModel, attributeValues);
        // TODO: Throw some sort of error.
    }

    public static ProtocolMapperModel createAttributeMapper(String name, String userAttribute,
                                                            String samlAttributeName, String nameFormat, String friendlyName) {
        String mapperId = PROVIDER_ID;
        return AttributeStatementHelper.createAttributeMapper(name, userAttribute, samlAttributeName, nameFormat, friendlyName,
                mapperId);
    }
}
