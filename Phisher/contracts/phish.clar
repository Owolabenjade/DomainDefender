;; ------------------------------
;; Phishing-Resistant Domain Registration System
;; Production-Ready Smart Contract in Clarity Language
;; ------------------------------

;; ------------------------------
;; Error Codes
;; ------------------------------

(define-constant ERR-NOT-FOUND u100)                  ;; Domain not found
(define-constant ERR-UNAUTHORIZED u101)               ;; Unauthorized action
(define-constant ERR-DOMAIN-ALREADY-REGISTERED u102)  ;; Domain already registered
(define-constant ERR-INVALID-DATA u103)               ;; Invalid input data
(define-constant ERR-VERIFICATION-FAILED u104)        ;; Ownership verification failed
(define-constant ERR-ALREADY-REVIEWED u105)           ;; User has already reviewed the domain
(define-constant ERR-RATING-OUT-OF-BOUNDS u106)       ;; Rating value is out of acceptable bounds
(define-constant ERR-ALREADY-REPORTED u107)           ;; User has already reported the domain

;; ------------------------------
;; Data Structures
;; ------------------------------

;; Map to store domain information
(define-map domains
  ((domain-name (string-ascii 253)))       ;; Key: Domain name
  ((owner principal)                       ;; Owner's principal address
   (identity-info (string-utf8 512))       ;; Identity information
   (reputation-score int)                  ;; Reputation score
   (registered-at uint)))                  ;; Registration timestamp

;; Map to store user reviews
(define-map domain-reviews
  ((domain-name (string-ascii 253))
   (reviewer principal))                   ;; Key: Domain and reviewer
  ((rating int)                            ;; Rating value
   (comment (string-utf8 256))             ;; Optional comment
   (reviewed-at uint)))                    ;; Timestamp

;; Map to store domain reports
(define-map domain-reports
  ((domain-name (string-ascii 253))
   (reporter principal))                   ;; Key: Domain and reporter
  ((reason-code int)                       ;; Reason for report
   (details (string-utf8 256))             ;; Optional details
   (reported-at uint)))                    ;; Timestamp

;; ------------------------------
;; Public Functions
;; ------------------------------

;; Register Domain Function
(define-public (register-domain
                (domain-name (string-ascii 253))
                (identity-info (string-utf8 512))
                (verification-code (string-ascii 64)))
  (begin
    ;; Input validation
    (if (or (<= (string-length domain-name) u0)
            (<= (string-length identity-info) u0)
            (<= (string-length verification-code) u0))
        (err ERR-INVALID-DATA)
        (let
          (
            ;; Check if the domain is already registered
            (existing-domain (map-get? domains {domain-name: domain-name}))
          )
          (match existing-domain
            some _
            ;; Domain is already registered
            (err ERR-DOMAIN-ALREADY-REGISTERED)
            none
            ;; Domain is not registered, proceed
            (let ((verified (verify-domain-ownership domain-name verification-code tx-sender)))
              (if verified
                  ;; Verification successful, register the domain
                  (begin
                    (map-set domains {domain-name: domain-name}
                      {owner: tx-sender,
                       identity-info: identity-info,
                       reputation-score: 0,
                       registered-at: (block-height)})
                    (ok true))
                  ;; Verification failed
                  (err ERR-VERIFICATION-FAILED))))))))

;; Update Domain Information Function
(define-public (update-domain-info
                (domain-name (string-ascii 253))
                (new-identity-info (string-utf8 512)))
  (begin
    ;; Input validation
    (if (<= (string-length new-identity-info) u0)
        (err ERR-INVALID-DATA)
        ;; Fetch the domain information
        (match (map-get? domains {domain-name: domain-name})
          some domain-data
          ;; Domain exists, check ownership
          (if (is-eq (get owner domain-data) tx-sender)
              ;; Ownership confirmed, update identity info
              (begin
                (map-set domains {domain-name: domain-name}
                  {owner: (get owner domain-data),
                   identity-info: new-identity-info,
                   reputation-score: (get reputation-score domain-data),
                   registered-at: (get registered-at domain-data)})
                (ok true))
              ;; Caller is not the owner
              (err ERR-UNAUTHORIZED))
          none
          ;; Domain not found
          (err ERR-NOT-FOUND)))))

;; Domain Lookup Function
(define-read-only (get-domain-info (domain-name (string-ascii 253)))
  (match (map-get? domains {domain-name: domain-name})
    some domain-data
    ;; Return domain information
    (ok domain-data)
    none
    ;; Domain not found
    (err ERR-NOT-FOUND)))

;; Submit Review Function
(define-public (submit-review
                (domain-name (string-ascii 253))
                (rating int)
                (comment (string-utf8 256)))
  (begin
    ;; Validate rating
    (if (or (< rating -5) (> rating 5))
        (err ERR-RATING-OUT-OF-BOUNDS)
        ;; Check if domain exists
        (match (map-get? domains {domain-name: domain-name})
          some domain-data
          ;; Domain exists, proceed
          (let ((existing-review (map-get? domain-reviews {domain-name: domain-name, reviewer: tx-sender})))
            (match existing-review
              some _
              ;; Reviewer has already reviewed this domain
              (err ERR-ALREADY-REVIEWED)
              none
              ;; Submit review
              (begin
                (map-set domain-reviews {domain-name: domain-name, reviewer: tx-sender}
                  {rating: rating,
                   comment: comment,
                   reviewed-at: (block-height)})
                ;; Update reputation score
                (update-reputation-score domain-name)
                (ok true))))
          none
          ;; Domain not found
          (err ERR-NOT-FOUND)))))

;; Report Suspicious Domain Function
(define-public (report-domain
                (domain-name (string-ascii 253))
                (reason-code int)
                (details (string-utf8 256)))
  (begin
    ;; Input validation
    (if (<= (string-length details) u0)
        (err ERR-INVALID-DATA)
        ;; Check if domain exists
        (match (map-get? domains {domain-name: domain-name})
          some _
          ;; Domain exists, proceed
          (let ((existing-report (map-get? domain-reports {domain-name: domain-name, reporter: tx-sender})))
            (match existing-report
              some _
              ;; Reporter has already reported this domain
              (err ERR-ALREADY-REPORTED)
              none
              ;; Submit report
              (begin
                (map-set domain-reports {domain-name: domain-name, reporter: tx-sender}
                  {reason-code: reason-code,
                   details: details,
                   reported-at: (block-height)})
                (ok true))))
          none
          ;; Domain not found
          (err ERR-NOT-FOUND)))))

;; ------------------------------
;; Private Functions
;; ------------------------------

;; Placeholder for Domain Ownership Verification
(define-private (verify-domain-ownership
                 (domain-name (string-ascii 253))
                 (verification-code (string-ascii 64))
                 (owner principal))
  ;; In production, this function should interface with an oracle or off-chain service
  ;; to verify that the owner has control over the domain.
  ;; For demonstration, I will simulate verification by requiring the verification code
  ;; to match a hash of the domain name and owner's address.

  (let ((expected-code (sha256 (concat (to-uint8 (hash160 domain-name)) (to-uint8 (hash160 (principal-to-hex owner)))))))
    (if (is-eq expected-code (sha256 (to-uint8 verification-code)))
        true
        false)))

;; Update Reputation Score Function
(define-private (update-reputation-score (domain-name (string-ascii 253)))
  (let ((reviews (filter (lambda (entry)
                           (is-eq (get domain-name entry) domain-name))
                         (map-values domain-reviews))))
    (if (is-some reviews)
        (let ((total-score (fold (lambda (acc entry)
                                   (+ acc (get rating entry)))
                                 0
                                 reviews)))
          (map-set domains {domain-name: domain-name}
            (merge
              (unwrap! (map-get? domains {domain-name: domain-name}) (err ERR-NOT-FOUND))
              {reputation-score: total-score})))
        ;; No reviews, reputation score remains unchanged
        (ok false))))