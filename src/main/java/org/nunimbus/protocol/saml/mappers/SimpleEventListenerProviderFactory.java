package org.nunimbus.protocol.saml.mappers;

import java.util.stream.Stream;

import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.UserModel;
import org.keycloak.models.RealmModel;

public class SimpleEventListenerProviderFactory implements EventListenerProviderFactory {

    private static final String ID = "event-listener-remove-group";

    @Override
    public EventListenerProvider create(KeycloakSession session) {
        return new SimpleEventListenerProvider(session);
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    	factory.register(
       		(event) -> {
       			if (event instanceof UserModel.UserRemovedEvent) {
    				UserModel user = ((UserModel.UserRemovedEvent) event).getUser();
    				RealmModel realm = ((UserModel.UserRemovedEvent) event).getRealm();
    				String username = user.getUsername();
    				
    				Stream<GroupModel> groups = user.getGroupsStream("admin-" + user.getUsername(),null,null);
    				long groupCount = user.getGroupsStream("admin-" + user.getUsername(),null,null).count();

    				if (groupCount == 1) {
    					groups.forEach(g-> {
    						if (user.isMemberOf(g)) {
    							realm.removeGroup(g);
    						}
    					});
    				}
   				}
   			}
       	);
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return ID;
    }
}
