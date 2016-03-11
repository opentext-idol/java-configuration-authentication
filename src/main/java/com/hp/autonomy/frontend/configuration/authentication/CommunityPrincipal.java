/*
 * Copyright 2014-2015 Hewlett-Packard Development Company, L.P.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

package com.hp.autonomy.frontend.configuration.authentication;

import lombok.Data;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

@Data
public class CommunityPrincipal implements Principal {
    private final long id;
    private final String username;
    @SuppressWarnings("MismatchedQueryAndUpdateOfCollection")
    private final List<String> roles;
    private final String securityInfo;

    @Override
    public String getName() {
        return username;
    }

    public List<String> getRoles() {
        return new ArrayList<>(roles);
    }
}
