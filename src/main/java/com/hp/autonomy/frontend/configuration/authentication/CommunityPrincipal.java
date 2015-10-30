/*
 * Copyright 2014-2015 Hewlett-Packard Development Company, L.P.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

package com.hp.autonomy.frontend.configuration.authentication;

import lombok.Data;

import java.security.Principal;

@Data
public class CommunityPrincipal implements Principal {
    private final long id;
    private final String username;

    @Override
    public String getName() {
        return username;
    }
}
