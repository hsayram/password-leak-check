import requests
import hashlib
import sys


def get_hashed_password(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    return sha1password


def get_leaked_passwords_hashes(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    response = requests.get(url)
    if response.status_code != 200:
        raise RuntimeError(
            f'Error fetching: {response.status_code}. Check the API and try again!')
    hashes_leaked = (line.split(':')
                     for line in response.text.splitlines())
    return hashes_leaked


def get_password_leaks_count(hashes_leaked, hash_to_check):
    for hash, count in hashes_leaked:
        if hash == hash_to_check:
            return count
    return 0


def check_if_password_is_pwned(password):
    sha1password = get_hashed_password(password)
    first5_char, tail = sha1password[:5], sha1password[5:]
    hashes_leaked = get_leaked_passwords_hashes(first5_char)
    return get_password_leaks_count(hashes_leaked, tail)


def main():
    with open('password.txt', 'r') as file:
        password = file.readline()
    pwned = check_if_password_is_pwned(password)
    if pwned == 0:
        print('Your password was not leaked!')
    else:
        print(f'Your password was leaked {pwned} times!',
              'You should change it!')


if __name__ == "__main__":
    sys.exit(main())
