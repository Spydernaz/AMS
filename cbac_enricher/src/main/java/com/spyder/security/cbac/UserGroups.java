
/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package com.spyder.security.cbac;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Hashtable;
import java.util.List;


public abstract class SAPSecurityFilter implements Filter {

protected abstract SAPPrincipal buildGroups(SAPPrincipal principal, NamingEnumeration<SearchResult> results) throws NamingException;

private static final String SECURE_ENTERPRISE_DIRECTORY = "ldaps://ldap.abc.com:636/o=abc.com";
private static final String PRINCIPAL_NAME = "SAPPrincipal";
private static final String ENTERPRISE_DIRECTORY = "ldap://ldap.abc.com:389/o=abc.com";
private static final String USER_KEY = "HTTP_SM_USER";
private static final String BASE = "ou=Groups";
private static final String GROUP_QUERY = "(member:1.2.840.113556.1.4.1941:=(CN=UserName,CN=Users,DC=YOURDOMAIN,DC=NET))";
private final CacheManager cacheManager;

private List<String> excludeUrlPatterns = new ArrayList<String>();


/**
 * doFilter
 * <p/>
 * Read the request headers for the HTTP_SM_USER value
 * This value is the users email address.
 * Using the email address lookup the users values in Enterprise directory
 * Populate the principal and place it in request scope.
 */
public void doFilter(ServletRequest request, ServletResponse response,
                        FilterChain chain) throws IOException, ServletException {

    //SAPt the request into HttpServletRequest
    String path = ((HttpServletRequest) request).getPathInfo();
    if (patternExcluded(path) || "OPTIONS".equalsIgnoreSAPe(((HttpServletRequest) request).getMethod())) {
        chain.doFilter(request, response);
    } else {
        String smUser = ((HttpServletRequest) request).getRemoteUser();
        HttpSession session = ((HttpServletRequest) request).getSession();
        if (smUser == null) throw new ServletException("USER TOKEN MISSING");

        // use the smUser to get the data needed to build a principal
        LdapContext ctx = null;
        // build SAP principal //
        SAPPrincipal principal = new SAPPrincipal();
        principal.setName(smUser);
        //Cache cache = cacheManager.getCache("principalCache");

        //Element element = cache.get(smUser);
        // Cache miss for user

        if (session.getAttribute(PRINCIPAL_NAME) == null) {

            try {
                ctx = getLdapContext(smUser);
                SearchControls constraints = new SearchControls();
                constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
                String[] attrs = {"cn"};
                constraints.setReturningAttributes(attrs);

                String filter = String.format(GROUP_QUERY, smUser);
                NamingEnumeration<SearchResult> results = ctx.search(BASE, filter, constraints);
                principal = buildGroups(principal, results);
                //cache.put(new Element(smUser, principal));
                session.setAttribute(PRINCIPAL_NAME, principal);
            } catch (NamingException ne) {
                throw new ServletException(ne);

            } finally {
                try {
                    if (ctx != null) ctx.close();
                } catch (NamingException ne) {
                    // swallow on purpose
                }
            }
            // Cache Hit for user
        } else {
            principal = (SAPPrincipal) session.getAttribute(PRINCIPAL_NAME);
        }

        // add principal to securityContext and SAPContext//
        SAPContext.setPrincipal(principal);
        chain.doFilter(new SecurityRequestWrapper(principal, (HttpServletRequest) request), response);
    }

}