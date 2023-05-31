/*
 * Copyright 2014-2015 Open Text.
 *
 * Licensed under the MIT License (the "License"); you may not use this file
 * except in compliance with the License.
 *
 * The only warranties for products and services of Open Text and its affiliates
 * and licensors ("Open Text") are as may be set forth in the express warranty
 * statements accompanying such products and services. Nothing herein should be
 * construed as constituting an additional warranty. Open Text shall not be
 * liable for technical or editorial errors or omissions contained herein. The
 * information contained herein is subject to change without notice.
 */

package com.hp.autonomy.frontend.configuration.authentication;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class Roles {

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
