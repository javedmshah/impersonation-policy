/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2009 Sun Microsystems Inc. All Rights Reserved
 *
 * The contents of this file are subject to the terms
 * of the Common Development and Distribution License
 * (the License). You may not use this file except in
 * compliance with the License.
 *
 * You can obtain a copy of the License at
 * https://opensso.dev.java.net/public/CDDLv1.0.html or
 * opensso/legal/CDDLv1.0.txt
 * See the License for the specific language governing
 * permission and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL
 * Header Notice in each file and include the License file
 * at opensso/legal/CDDLv1.0.txt.
 * If applicable, add the following below the CDDL Header,
 * with the fields enclosed by brackets [] replaced by
 * your own identifying information:
 * "Portions Copyrighted [year] [name of copyright owner]"
 *
 */

/*
 * author Javed Shah
 * 
 */

package org.forgerock.openam.authentication.modules.impersonation;

import java.io.Serializable;
import java.security.Principal;

/**
 * Represents the user's principle for the Device Print authentication module.
 */
public class ImpersonationModulePrincipal implements Principal, Serializable {

    private static final long serialVersionUID = 1L;
	private String name;

    public ImpersonationModulePrincipal(String name) {
        if (name == null) {
            throw new RuntimeException("illegal null input");
        }

        this.name = name;
    }

    /**
     * Return the LDAP username for this <code> IPSecurityModulePrincipal </code>.
     *
     * @return The LDAP username.
     */
    public String getName() {
        return name;
    }

    /**
     * Return a string representation of this <code> IPSecurityModulePrincipal </code>.
     *
     * @return A string representation of this <code>IPSecurityModulePrincipal</code>.
     */
    @Override
    public String toString() {
        return new StringBuilder()
                .append(ImpersonationModulePrincipal.class.getName())
                .append(":")
                .append(name)
                .toString();
    }

    /**
     * Compares the specified Object with this <code> IPSecurityModulePrincipal </code> for equality.  Returns true if
     * the given object is also a <code> IPSecurityModulePrincipal </code> and the two IPSecurityModulePrincipal have
     * the same username.
     *
     * @param o Object to be compared for equality with this <code> IPSecurityModulePrincipal </code>.
     *
     * @return true if the specified Object is equal equal to this <code> IPSecurityModulePrincipal </code>.
     */
    @Override
    public boolean equals(Object o) {
        if (o == null) {
            return false;
        }

        if (this == o) {
            return true;
        }

        if (!(o instanceof ImpersonationModulePrincipal)) {
            return false;
        }
        ImpersonationModulePrincipal that = (ImpersonationModulePrincipal) o;

        if (this.getName().equals(that.getName())) {
            return true;
        }
        return false;
    }

    /**
     * Return a hash code for this <code> IPSecurityModulePrincipal </code>.
     *
     * @return A hash code.
     */
    @Override
    public int hashCode() {
        return name.hashCode();
    }
}