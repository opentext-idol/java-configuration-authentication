/*
 * Copyright 2014-2015 Hewlett-Packard Development Company, L.P.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

package com.hp.autonomy.frontend.configuration.authentication;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;

import java.util.Collection;
import java.util.HashSet;
import java.util.Map;

/**
 * This maps the incoming granted authorities to the corresponding entries in the {@link #authorityMap}.
 */
public class OneToOneOrZeroSimpleAuthorityMapper implements GrantedAuthoritiesMapper {
    private final Map<String, String> authorityMap;

    /**
     * Constructs a new OneToOneOrZeroSimpleAuthorityMapper with the given authority map.
     * @param authorityMap A map from IDOL Community roles to application roles.
     */
    public OneToOneOrZeroSimpleAuthorityMapper(final Map<String, String> authorityMap) {
        this.authorityMap = authorityMap;
    }

    @Override
    public Collection<? extends GrantedAuthority> mapAuthorities(final Collection<? extends GrantedAuthority> authorities) {
        final Collection<GrantedAuthority> output = new HashSet<>();

        for (final GrantedAuthority authority : authorities) {
            final String mappedAuthority = authorityMap.get(authority.getAuthority());

            if (mappedAuthority != null) {
                output.add(new SimpleGrantedAuthority(mappedAuthority));
            }
        }

        return output;
    }
}
