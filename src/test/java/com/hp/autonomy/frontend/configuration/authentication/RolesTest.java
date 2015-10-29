package com.autonomy.login.role;

import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;
import java.util.HashSet;

import static org.junit.Assert.*;

public class RolesTest {

    private Roles roles;

    @Before
    public void setUp() throws Exception {
        roles = new Roles();

        final Role user = new RoleFactory().setName("user").setPrivileges(new HashSet<>(Arrays.asList("read", "execute"))).getObject();
        final Role superuser = new RoleFactory().setName("superuser").setPrivileges(new HashSet<>(Arrays.asList("read", "execute", "write"))).getObject();
        final Role admin = new RoleFactory().setName("admin").setPrivileges(new HashSet<>(Arrays.asList("read", "execute", "write", "create", "delete"))).getObject();
        final Role useradmin = new RoleFactory().setName("useradmin").setPrivileges(new HashSet<>(Arrays.asList("read", "execute", "create", "destroy"))).getObject();
        final Role loner = new RoleFactory().setName("loner").setPrivileges(new HashSet<>(Arrays.asList("think", "meditate", "thinkagain", "shout"))).getObject();

        user.getParent().add(superuser);
        superuser.getParent().add(useradmin);
        superuser.getParent().add(admin);

        this.roles.getRoles().addAll(Arrays.asList(user, superuser, admin, useradmin, loner));
    }

    @Test
    public void testGetRole(){
        assertEquals(this.roles.getRole("user").getName(), "user");
        assertEquals(this.roles.getRole("aaaaa"), null);
    }

    @Test
    public void testIsAuthorized(){
        assertTrue(this.roles.isAuthorized("destroy"));
        assertTrue(this.roles.isAuthorized("execute"));
        assertFalse(this.roles.isAuthorized("kill"));
    }

    @Test
    public void testAreRolesAuthorized(){
        assertTrue(this.roles.areRolesAuthorized(new HashSet<>(Arrays.asList("user", "superuser")), "execute"));
        assertTrue(this.roles.areRolesAuthorized(new HashSet<>(Arrays.asList("user", "superuser")), "write"));
        assertFalse(this.roles.areRolesAuthorized(new HashSet<>(Arrays.asList("loner")), "destroy"));

        assertFalse(this.roles.areRolesAuthorized(new HashSet<>(Arrays.asList("user", "superuser")), new HashSet<>(Arrays.asList("execute", "shout"))));
        assertTrue(this.roles.areRolesAuthorized(new HashSet<>(Arrays.asList("user", "loner")), new HashSet<>(Arrays.asList("execute", "shout"))));
        assertTrue(this.roles.areRolesAuthorized(new HashSet<>(Arrays.asList("user", "admin")), new HashSet<>(Arrays.asList("execute", "create"))));
        assertFalse(this.roles.areRolesAuthorized(new HashSet<>(Arrays.asList("user", "admin")), new HashSet<>(Arrays.asList("think", "meditate", "thinkagain", "shout"))));
        assertTrue(this.roles.areRolesAuthorized(new HashSet<>(Arrays.asList("loner")), new HashSet<>(Arrays.asList("think", "meditate", "thinkagain", "shout"))));
    }
}