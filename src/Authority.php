<?php

/*
 * 
 * Copyright (c) 2014 muhannad.
 * All rights reserved. This file is a property of Homely.ae.
 * 
 */

namespace ItvisionSy\LaravelRolesAuthorization;

use \Auth;
use \Config;

/**
 * Authority class is responsible about providing privilege checking information
 *  against an associative array from Config::get('roles');
 */
class Authority {

    /**
     * Checks the privilege for a $role to do a $verb, optionally against $specific object.
     * 
     * @param string $verb
     * @param mixed $specific
     * @param string|null $role the role to check its privilege. If null, current user's role will be used
     * @return boolean
     */
    public static function can($verb, $specific = null, $role = null) {
        $can = null;
        if (Auth::check()) {
            if ($role === null) {
                $role = Auth::user()->type;
            }
            $current = strtolower($role);
            $privs = Config::get("roles.privileges." . strtolower($verb), []);
            $can = array_search($current, @$privs["deny"]? : []) !== false ? false : (array_search($current, @$privs["allow"]? : []) !== false ? true : null);
            if ($can === null) {
                $can = call_user_func(
                        @$privs[$current]? : (
                                @$privs['custom']? : function() {
                                    return false;
                                }), $specific);
                $can = $can === null ? false : $can;
            }
        } else {
            $can = false;
            //TODO: check visitor privs. i.e. access country, deny ip, ...
        }
        return $can;
    }

    /**
     * Describes a verb, optionally for a role (will use verb:role if present)
     * 
     * @param string $verb
     * @param string $role
     * @return string
     */
    public static function describe($verb, $role = null) {
        if ($role === null) {
            $role = strtolower(Auth::check() ? Auth::user()->type : "");
        }
        $privs = Config::get("roles.privileges." . strtolower($verb), []);
        if (array_key_exists("description:$role", $privs)) {
            return $privs["description:$role"];
        } else {
            return @$privs["description"]? : "";
        }
    }

    /**
     * Get the title of a verb
     * 
     * @param string $verb
     * @return string
     */
    public static function title($verb) {
        $privs = Config::get("roles.privileges." . strtolower($verb), []);
        return @$privs["title"]? : "";
    }

    /**
     * List the privileges for a role (just listing).
     * 
     * @param string $role
     * @param array $skipRoles
     * @return array
     */
    public static function privileges($role = null, array $skipRoles = []) {
        if ($role === null) {
            $role = strtolower(Auth::check() ? Auth::user()->type : "");
        }
        $roles = Config::get("roles.roles");
        $privs = @$roles[$role]? : [];
        $includes = @$privs["_includes"]? : [];
        if (array_key_exists("_includes", $privs)) {
            unset($privs["_includes"]);
        }
        $skipRoles[] = $role;
        foreach ($includes as $include) {
            if (array_search($include, $skipRoles)) {
                continue;
            }
            $skipRoles[] = $include;
            $privs = array_merge($privs, self::privileges($include, $skipRoles));
        }
        return array_unique($privs);
    }

}
