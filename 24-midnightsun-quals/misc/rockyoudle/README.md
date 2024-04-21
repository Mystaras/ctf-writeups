# Rockyoudle
Mastermind game using dictionary

## Presentation
We are given a large dictionary and have to decrease the number of contenders. What we know about the word:
- The size of the word
- The character is either a number or a letter (no special chars and Capitalisation is not important)
- If a character is correct and at the correct position
- If a character is correct but at the wrong posistion
- If a character does not exist in the word

Using this we can slowly reduce the number of potential dictionary words untill a good threshold after which we start bruteforcing.

## Solution algorithm
```python

def try_word(secret):
  return 3 lists:
  - list of characters that were at the correct position (correct)  
  - list of characters that where at the wrong position (wrong_pos)
  - list of characters that where not correct and not at the wrong position (wrong)

  # e.g. Real secret is "1234" and we attempted "1245":
  # - correct = ['1', '2', Null, Null]
  # - wrong_pos = [Null, Null, 4, Null]
  # - wrong = [5]
  # So next try we will try to insert 4 at a different index (3) than it was (2).


def filter_dictionary(correct, wrong_pos, wrong):
  Remove from the dictionary words that have characters that don't exist (wrong)
  # In the above example, all words that contain a '5'

  Remove from the dictionary words that don't have the correct characters at the correct index (correct)
  # In the above example, all words where the 1st and 2nd character are not '1', '2'

  Remove from the dictionary words that have characters in the position that was wrong (wrong_pos)
  # In the above example, all words that have a '4' as their 3rd character

  Remove all words that don't have the contender character (wrong_pos)
  # In the above example all words that don't have a '4'


list alphabet := numbers + most_common_letters_alphabet + rest_alphabet
list dictionary := words that have a lenght equal to the secret

list correct[size_word] := [Null, ...]
list wrong_pos[size_word] := [Null, ...]
list wrong := []

dict GLOBAL_wrong_position
for i := 0 to size(alphabet):
  GLOBAL_wrong_position[alphabet[i]] := []

while True:

  for i := 0 to size_word:
    if (c := wrong_pos[i]) != Null:
      j := index to insert potential contender that should be different than `i` and not in GLOBAL_wrong_position[c].
      secret[j] := c

      # update GLOBAL_wrong_position to keep track of which indexes have been tried for this character:
      GLOBAL_wrong_positon[c] += j 

  replace all Null idexes in `secret` with `alphabet.pop(0)`. If `alphabet` gets empty, repopulate to handle words with duplicate characters.
  correct, wrong_pos, wrong = try_word(secret)
  filter_dictionary(correct, wrong_pos, wrong)

  

  if size(dictionary) < threshold:
    while True:
      secret := dictionary.pop()
      correct, wrong_pos, wrong = try_word(secret)
      filter_dictionary(correct, wrong_pos, wrong)  
```


  

