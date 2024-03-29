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

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class LoginSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    private final String configUrl;
    private final String applicationUrl;
    private final String roleDefault;

    public LoginSuccessHandler(final String roleDefault, final String configUrl, final String applicationUrl) {
        super();
        this.roleDefault = roleDefault;
        this.configUrl = configUrl;
        this.applicationUrl = applicationUrl;
    }

    @Override
    protected String determineTargetUrl(final HttpServletRequest request, final HttpServletResponse response) {
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        for(final GrantedAuthority grantedAuthority : authentication.getAuthorities()) {
            if(roleDefault.equalsIgnoreCase(grantedAuthority.getAuthority())) {
                return configUrl;
            }
        }

        return applicationUrl;
    }
}
