# Copyright (c) 2004-2011 Moxie Marlinspike
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
# USA
#


class CookieCleaner:
    """This class cleans cookies we haven't seen before.  The basic idea is to
    kill sessions, which isn't entirely straight-forward.  Since we want this to
    be generalised, there's no way for us to know exactly what cookie we're trying
    to kill, which also means we don't know what domain or path it has been set for.

    The rule with cookies is that specific overrides general.  So cookies that are
    set for mail.foo.com override cookies with the same name that are set for .foo.com,
    just as cookies that are set for foo.com/mail override cookies with the same name
    that are set for foo.com/

    The best we can do is guess, so we just try to cover our bases by expiring cookies
    in a few different ways.  The most obvious thing to do is look for individual cookies
    and nail the ones we haven't seen coming from the server, but the problem is that cookies are often
    set by Javascript instead of a Set-Cookie header, and if we block those, the site
    will think cookies are disabled in the browser.  So we do the expirations and allow-listing
    based on client, server tuples.  The first time a client hits a server, we kill whatever
    cookies we see then.  After that, we just let them through.  Not perfect, but pretty effective.

    """

    _instance = None

    @classmethod
    def getInstance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        self.cleaned_cookies = set()
        self.enabled = False

    def set_enabled(self, enabled):
        self.enabled = enabled

    def is_clean(self, method, client, host, headers):
        if method == 'POST' or not self.enabled or not self.has_cookies(headers):
            return True
        return (client, self.get_domain_for(host)) in self.cleaned_cookies

    def get_expire_headers(self, method, client, host, headers, path):
        domain = self.get_domain_for(host)
        self.cleaned_cookies.add((client, domain))

        expire_headers = []
        for cookie in headers['cookie'].split(';'):
            cookie = cookie.split('=')[0].strip()
            expire_headers.extend(self.get_expire_cookie_string_for(cookie, host, domain, path))

        return expire_headers

    @staticmethod
    def has_cookies(headers):
        return 'cookie' in headers

    @staticmethod
    def get_domain_for(host):
        host_parts = host.split('.')
        return '.' + host_parts[-2] + '.' + host_parts[-1]

    @staticmethod
    def get_expire_cookie_string_for(self, cookie, host, domain, path):
        path_list = path.split('/')
        expire_strings = []

        base_str_format = f'{cookie}=EXPIRED;Path={{}};Domain={{}};Expires=Mon, 01-Jan-1990 00:00:00 GMT\r\n'
        expire_strings.append(base_str_format.format('/', domain))
        expire_strings.append(base_str_format.format('/', host))

        if len(path_list) > 2:
            path_sub_part = '/' + path_list[1]
            expire_strings.append(base_str_format.format(path_sub_part, domain))
            expire_strings.append(base_str_format.format(path_sub_part, host))

        return expire_strings
