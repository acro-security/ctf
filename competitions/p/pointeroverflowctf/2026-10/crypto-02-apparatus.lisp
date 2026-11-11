;;; The final board has X at B C E G and O at A D I.
;;; Enumerate alternating moves, rejecting positions where either player
;;; wins before the final move. The cipher shifts all printable ASCII
;;; characters (space through tilde) by A=0, B=1, ..., Z=25.

(defparameter *winning-lines*
  '("ABC" "DEF" "GHI" "ADG" "BEH" "CFI" "AEI" "CEG"))

(defun winner-p (moves)
  (some (lambda (line) (every (lambda (square) (find square moves)) line))
        *winning-lines*))

(defun legal-keys ()
  (labels ((walk (x-left o-left x-played o-played sequence)
             (let ((turn (length sequence)))
               (cond
                 ((or (winner-p o-played)
                      (and (winner-p x-played) (< turn 7))) nil)
                 ((= turn 7) (when (winner-p x-played) (list sequence)))
                 ((evenp turn)
                  (loop for square across x-left
                        append (walk (remove square x-left :count 1) o-left
                                     (concatenate 'string x-played (string square))
                                     o-played (concatenate 'string sequence (string square)))))
                 (t
                  (loop for square across o-left
                        append (walk x-left (remove square o-left :count 1)
                                     x-played (concatenate 'string o-played (string square))
                                     (concatenate 'string sequence (string square)))))))))
    (walk "BCEG" "ADI" "" "" "")))

(defun decrypt (ciphertext key)
  (map 'string
       (lambda (character index)
         (let ((code (char-code character)))
           (unless (<= 32 code 126)
             (error "Ciphertext contains a non-printable ASCII character: ~S" character))
           (code-char (+ 32 (mod (- code 32
                                    (- (char-code (char key (mod index (length key))))
                                       (char-code #\A)))
                                 95)))))
       ciphertext (loop for i below (length ciphertext) collect i)))

(defparameter *primary*
  "QOGWL$7/1:4?6DGNZYJ]YHGZ\\:`TM.KEIb9YM:6XJR7YGF;:IZYVKK`\\~")
(defparameter *secondary*
  "Cy$vgtv!arg&j{!awk2(dz xkk(dseewn(fsa{q&jwu rrz(tftyutmf- {h&wrfn$wnm\"xa}1")

(let ((keys (legal-keys)))
  (format t "Legal keys: ~D~%" (length keys))
  ;; The short message provides a recognizable English phrase to identify
  ;; the key; inspect other candidates if the ciphertext changes.
  (dolist (key keys)
    (let ((message (decrypt *secondary* key)))
      (when (search " the " (string-downcase message))
        (format t "Key: ~A~%Primary: ~A~%Secondary: ~A~%"
                key (decrypt *primary* key) message)))))

;;; Legal keys: 108
;;; Key: BAEDGIC
;;; Primary: POCTF{5.1619.BFNVVDUWGGVY4XRL.GBCZ7XM63RBP6YCC52GYYRHEXZ}
;;; Secondary: By salt and by ash, by the breath drawn but not returned, we open the way.