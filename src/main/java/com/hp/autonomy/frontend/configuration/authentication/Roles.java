/*
 * Copyright 2014-2015 Hewlett-Packard Development Company, L.P.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

package com.hp.autonomy.frontend.configuration.authentication;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@AllArgsConstructor
@NoArgsConstructor
public class Roles {

    @Getter
    @Setter
    private List<Role> roles = new ArrayList<>();

    public Role getRole(final String name){
        for(final Role role : this.roles){
            if(role.getName().equals(name)){
                return role;
            }
        }

        return null;
    }

    public boolean isAuthorized(final String privilege){
        for(final Role role : this.roles){
            if(role.isAuthorized(privilege)){
                return true;
            }
        }

        return false;
    }

    public boolean areRolesAuthorized(final Set<String> roleNames, final String privilege){
        for(final String roleName : roleNames){
            final Role role = this.getRole(roleName);
            if(role != null && role.isAuthorized(privilege)){
                return true;
            }
        }

        return false;
    }

    public boolean areRolesAuthorized(final Set<String> roleNames, final Set<String> privileges){
        for(final String privilege : privileges){
            if(!this.areRolesAuthorized(roleNames, privilege)){
                return false;
            }
        }

        return true;
    }
}
