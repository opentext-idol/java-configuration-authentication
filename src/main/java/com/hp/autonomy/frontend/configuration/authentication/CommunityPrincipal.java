/*
 * (c) Copyright 2014-2015 Micro Focus or one of its affiliates.
 *
 * Licensed under the MIT License (the "License"); you may not use this file
 * except in compliance with the License.
 *
 * The only warranties for products and services of Micro Focus and its affiliates
 * and licensors ("Micro Focus") are as may be set forth in the express warranty
 * statements accompanying such products and services. Nothing herein should be
 * construed as constituting an additional warranty. Micro Focus shall not be
 * liable for technical or editorial errors or omissions contained herein. The
 * information contained herein is subject to change without notice.
 */

package com.hp.autonomy.frontend.configuration.authentication;

import lombok.Data;

import java.io.Serializable;
import java.security.Principal;
import java.util.Map;
import java.util.Set;

@SuppressWarnings("WeakerAccess")
@Data
public class CommunityPrincipal implements Principal, Serializable {
    private static final long serialVersionUID = -8625590848187633506L;

    private final long id;
    private final String username;
    private final String securityInfo;
    private final Set<String> idolRoles;
    private final Map<String, String> fields;

    @Override
    public String getName() {
        return username;
    }
}
