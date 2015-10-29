/*
 * Copyright 2014-2015 Hewlett-Packard Development Company, L.P.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

package com.hp.autonomy.frontend.configuration.authentication;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Setter;
import lombok.experimental.Accessors;

import java.util.HashSet;
import java.util.Set;

@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Data
public class Role {

    private final String name;
    private final Set<String> privileges;
    private final Set<Role> parent;
    private final String sessionAttribute;

    public Role getParent(final String roleName){
        for(final Role role : this.parent){
            if(role.getName().equals(roleName)){
                return role;
            }
        }

        return null;
    }

    public Set<Role> getAncestors(){
        final Set<Role> ancestors = new HashSet<>();
        this.getRecursiveAncestors(this.getParent(), ancestors);

        return ancestors;
    }

    public boolean isAuthorized(final String privilege){
        if(this.privileges.contains(privilege)){
            return true;
        }

        for(final Role role: this.getAncestors()){
            if(role.getPrivileges().contains(privilege)){
                return true;
            }
        }

        return false;
    }

    public boolean isAuthorized(final Set<String> privileges){
        for(final String privilege : privileges){
            if(!this.isAuthorized(privilege)){
                return false;
            }
        }

        return true;
    }

    private void getRecursiveAncestors(final Set<Role> roles, final Set<Role> ancestors){
        for(final Role role : roles){
            this.getRecursiveAncestors(role, ancestors);
        }
    }

    private void getRecursiveAncestors(final Role role, final Set<Role> ancestors){
        ancestors.add(role);

        if(role.getParent().isEmpty()) {
            return;
        }

        this.getRecursiveAncestors(role.getParent(), ancestors);
    }

    @Setter
    @Accessors(chain = true)
    public static class Builder {

        private String name;
        private Set<String> privileges = new HashSet<>();
        private Set<Role> parent = new HashSet<>();
        private String sessionAttribute;

        public Role build() {
            return new Role(name, privileges, parent, sessionAttribute);
        }

    }
}
