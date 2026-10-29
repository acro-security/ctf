;;; Letters Never Sent
;;;
;;; The red stars mark Tulip, Anchor, Lily, Lily, Oak, and Willow.
;;; Reading clockwise from the top and taking initials gives TALLOW.
;;; Francis Beaufort and the "reciprocal tableau" suggest the Beaufort cipher.
;;; For each letter, plaintext = (key - ciphertext) mod 26. Punctuation and
;;; digits are preserved and do not advance the key.

(defun beaufort (text key)
  "Apply the reciprocal Beaufort cipher to ASCII letters in TEXT."
  (unless (and (plusp (length key))
               (every (lambda (c) (and (char<= #\A c) (char<= c #\Z))) key))
    (error "The key must contain only uppercase ASCII letters."))
  (let ((position 0))
    (map 'string
         (lambda (c)
           (if (and (char<= #\A c) (char<= c #\Z))
               (prog1
                   (code-char (+ (char-code #\A)
                                 (mod (- (char-code (char key (mod position (length key))))
                                         (char-code c))
                                      26)))
                 (incf position))
               c))
         text)))

(let ((ciphertext "EMJSJ{2.1619.TQIQFV4AQTM47QAL.JGCMS6O6XPI4LOFDSKARDNR7EM}"))
  (format t "~A~%" (beaufort ciphertext "TALLOW")))

;;; POCTF{2.1619.DDSVGT4WDHZ47VOL.KUJZW6I6WLD4AARQIBLXTGJ7HZ}
