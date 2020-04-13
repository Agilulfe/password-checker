# -*- coding: utf-8 -*-
"""
Encode your password and call pwnedpasswords API to see if it has been leaked
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

"""
import requests
import hashlib
import sys


def main(args: list):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(
                f'{password} was found {count} times... you should probably change your password!')
        else:
            print(f'{password} was NOT found. Carry on!')
    return 'done!'


def pwned_api_check(password: str):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)


def request_api_data(first5_char: str):
    url = 'https://api.pwnedpasswords.com/range/' + first5_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(
            f'Error fetching: {res.status_code}, check the api and try again')
    return res


def get_password_leaks_count(response: requests.Response, tail: str):
    response = (line.split(':') for line in response.text.splitlines())
    for h, count in response:
        if h == tail:
            return count
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
