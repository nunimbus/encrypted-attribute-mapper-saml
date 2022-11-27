/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.nunimbus.protocol.saml.mappers;

/**
 * Maps an encrypted custom user attribute to a to a SAML client attribute
 * 
 * To enable:
 * - Create a SAML client (varies by requirement)
 * - Under the client settings, select the "Mappers" tab
 * - Click "Create"
 * - Provide a name for the mapper (user preference)
 * - Select "Encrypted User Attribute" from the Mapper Type dropdown
 * - Provide the name of the User Attribute to be decrypted and mapped
 * - Provide the SAML Attribute Name for the attribute to be mapped
 * - Select "Basic" from the SAML Attribute NameFormat dropdown
 * - Click "Save"
 *
 * @author Andrew Summers
 * @version $Revision: 1 $
 */
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
//import org.keycloak.services.ErrorPage;
//import org.keycloak.services.messages.Messages;

import util.CryptoUtils;
import util.StreamsForEach;
import java.util.Collection;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

/**
 * Mappings UserModel attribute (not property name of a getter method) to an AttributeStatement.
 */
public class UserEncryptedAttributeStatementMapper extends AbstractSAMLProtocolMapper implements SAMLAttributeStatementMapper {
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

    public static final String PROVIDER_ID = "saml-encrypted-user-attribute-mapper";


    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }
    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Encrypted User Attribute";
    }

    @Override
    public String getDisplayCategory() {
        return AttributeStatementHelper.ATTRIBUTE_STATEMENT_CATEGORY;
    }

    @Override
    public String getHelpText() {
        return "Map an encrypted custom user attribute to a to a SAML attribute.";
    }

    @Override
    public void transformAttributeStatement(AttributeStatementType attributeStatement, ProtocolMapperModel mappingModel, KeycloakSession session, UserSessionModel userSession, AuthenticatedClientSessionModel clientSession) {
    	UserModel user = userSession.getUser();
        String attributeName = mappingModel.getConfig().get(ProtocolMapperUtils.USER_ATTRIBUTE);
        boolean aggregateAttrs = Boolean.valueOf(mappingModel.getConfig().get(ProtocolMapperUtils.AGGREGATE_ATTRS));
        Collection<String> attributeValues = KeycloakModelUtils.resolveAttribute(user, attributeName, aggregateAttrs);
        if (attributeValues.isEmpty()) return;

        RealmModel realm = userSession.getRealm();
        String encrypted = attributeValues.toArray()[0].toString();
        
        // Deprecated. Recommended to use PasswordCredentialModel.getSecretData().getValue() or OTPCredentialModel.getSecretData().getValue()
        String currentCredential = user.credentialManager().getStoredCredentialsStream().sorted(CredentialModel.comparingByStartDateDesc()).findFirst().get().getValue();
        Stream<CredentialModel> credentials = user.credentialManager().getStoredCredentialsStream().sorted(CredentialModel.comparingByStartDateDesc());
        
        // Loop through all credentials in the user's history and try to decrypt the secret. Then, re-encrypt the secret with the current credential.
        StreamsForEach.forEach(credentials, (c, breaker) -> {
	        try {
	        	String credential = c.getValue();
				String key = CryptoUtils.decrypt(encrypted, credential);

/*				if (1==1) {
					ErrorPage.error(session, null, Response.Status.BAD_REQUEST, "A really bad thing happened");
					AuthenticationManager.browserLogout(session, realm, userSession, session.getContext().getUri(), session.getContext().getConnection(), session.getContext().getRequestHeaders(), null);
			        session.getContext().getRequestHeaders().getCookies().forEach((name, cookie)-> {
			        	String domain = cookie.getDomain();
			        	if (domain.isBlank()) {
			        		domain = session.getContext().getUri().getBaseUri().getHost();
			        	}
			        	
			        	String path = cookie.getPath();
			        	if (path.isBlank()) {
			        		path = "/";
			        	}
			        	
			        	CookieHelper.addCookie(cookie.getName(), cookie.getValue(), path, domain, null, -99999999, true, false);
			        });
					session.close();
					
					session.authenticationSessions().close();
				}
*/
/*
				System.err.println("Mapping encrypted attribute");
		    	System.err.println(new Throwable().getStackTrace()[0].getFileName() + ":" + new Throwable().getStackTrace()[0].getLineNumber());
				System.err.println("Encrypted:   " + encrypted.substring(0, 8));
				System.err.println("Credential:  " + credential.substring(0, 8));
				System.err.println("Key:         " + key.substring(0, 8));
				System.err.println();
				System.err.println();
/**/

				if (! currentCredential.equals(credential)) {
					String encryptedNew = CryptoUtils.encrypt(key, currentCredential);
					user.setSingleAttribute(attributeName, encryptedNew);
				}
				else {
					String encryptedNew = CryptoUtils.encrypt(key, credential);
					user.setSingleAttribute(attributeName, encryptedNew);					
				}
				
				attributeValues.clear();
				attributeValues.add(key);
				breaker.stop();
			} catch (Exception e) {
				System.err.println("ERROR: " + new Throwable().getStackTrace()[0].getFileName() + ":" + new Throwable().getStackTrace()[0].getLineNumber());
				//e.printStackTrace();
			}
		});

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
