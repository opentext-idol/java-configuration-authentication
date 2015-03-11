/*
 * Copyright 2014-2015 Hewlett-Packard Development Company, L.P.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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
