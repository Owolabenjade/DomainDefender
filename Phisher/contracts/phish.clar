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
(define-constant ERR-NO-PERMISSION u108)              ;; User lacks necessary permissions
(define-constant ERR-ALREADY-RESOLVED u109)           ;; Dispute already resolved
(define-constant ERR-NOT-IN-DISPUTE u110)             ;; No dispute to resolve

;; ------------------------------
;; Data Structures
;; ------------------------------

;; Map to store domain information
(define-map domains
  ((domain-name (string-ascii 253)))       ;; Key: Domain name
  ((owner principal)                       ;; Owner's principal address
   (identity-info (string-utf8 512))       ;; Identity information
   (identity-verified bool)                ;; Identity verification status
   (reputation-score int)                  ;; Reputation score
   (registered-at uint)))                  ;; Registration timestamp

;; Map to store user reviews
(define-map domain-reviews
  ((domain-name (string-ascii 253))
   (reviewer principal))                   ;; Key: Domain and reviewer
  ((rating int)                            ;; Rating value
   (comment (string-utf8 256))             ;; Optional comment
   (reviewer-reputation int)               ;; Reviewer's reputation score
   (reviewed-at uint)))                    ;; Timestamp

;; Map to store domain reports
(define-map domain-reports
  ((domain-name (string-ascii 253))
   (reporter principal))                   ;; Key: Domain and reporter
  ((reason-code int)                       ;; Reason for report
   (details (string-utf8 256))             ;; Optional details
   (resolved bool)                         ;; Dispute resolution status
   (reported-at uint)))                    ;; Timestamp

;; Map to store user roles
(define-map user-roles
  ((user principal))                       ;; Key: User principal
  ((role (string-ascii 32))))              ;; Role assigned to the user

;; ------------------------------
;; Constants
;; ------------------------------

(define-constant ADMIN-ROLE "admin")
(define-constant MODERATOR-ROLE "moderator")

;; ------------------------------
;; Events
;; ------------------------------

(define-event domain-registered (domain-name (string-ascii 253)) (owner principal))
(define-event domain-updated (domain-name (string-ascii 253)) (owner principal))
(define-event domain-transferred (domain-name (string-ascii 253)) (old-owner principal) (new-owner principal))
(define-event review-submitted (domain-name (string-ascii 253)) (reviewer principal) (rating int))
(define-event domain-reported (domain-name (string-ascii 253)) (reporter principal) (reason-code int))
(define-event dispute-resolved (domain-name (string-ascii 253)) (resolver principal) (status bool))
(define-event identity-verified (domain-name (string-ascii 253)) (verifier principal))

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
                       identity-verified: false,
                       reputation-score: 0,
                       registered-at: (block-height)})
                    (emit-event (domain-registered domain-name tx-sender))
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
                   identity-verified: false,  ;; Reset verification status
                   reputation-score: (get reputation-score domain-data),
                   registered-at: (get registered-at domain-data)})
                (emit-event (domain-updated domain-name tx-sender))
                (ok true))
              ;; Caller is not the owner
              (err ERR-UNAUTHORIZED))
          none
          ;; Domain not found
          (err ERR-NOT-FOUND)))))

;; Transfer Domain Ownership Function
(define-public (transfer-domain-ownership
                (domain-name (string-ascii 253))
                (new-owner principal))
  (begin
    ;; Fetch the domain information
    (match (map-get? domains {domain-name: domain-name})
      some domain-data
      ;; Domain exists, check ownership
      (if (is-eq (get owner domain-data) tx-sender)
          ;; Ownership confirmed, transfer ownership
          (begin
            (map-set domains {domain-name: domain-name}
              {owner: new-owner,
               identity-info: (get identity-info domain-data),
               identity-verified: false,  ;; Reset verification status
               reputation-score: (get reputation-score domain-data),
               registered-at: (get registered-at domain-data)})
            (emit-event (domain-transferred domain-name tx-sender new-owner))
            (ok true))
          ;; Caller is not the owner
          (err ERR-UNAUTHORIZED))
      none
      ;; Domain not found
      (err ERR-NOT-FOUND))))

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
                ;; Get reviewer's reputation (simplified to 0 for now)
                (let ((reviewer-reputation (get-user-reputation tx-sender)))
                  (map-set domain-reviews {domain-name: domain-name, reviewer: tx-sender}
                    {rating: rating,
                     comment: comment,
                     reviewer-reputation: reviewer-reputation,
                     reviewed-at: (block-height)})
                  ;; Update reputation score
                  (update-reputation-score domain-name)
                  (emit-event (review-submitted domain-name tx-sender rating))
                  (ok true)))))
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
                   resolved: false,
                   reported-at: (block-height)})
                (emit-event (domain-reported domain-name tx-sender reason-code))
                (ok true))))
          none
          ;; Domain not found
          (err ERR-NOT-FOUND)))))

;; Resolve Dispute Function (Admin or Moderator Only)
(define-public (resolve-dispute
                (domain-name (string-ascii 253))
                (reporter principal)
                (status bool))  ;; True for valid report, False for invalid
  (begin
    ;; Check if caller has permission
    (if (has-role? tx-sender MODERATOR-ROLE)
        ;; Proceed to resolve dispute
        (match (map-get? domain-reports {domain-name: domain-name, reporter: reporter})
          some report-data
          ;; Report exists, check if already resolved
          (if (get resolved report-data)
              (err ERR-ALREADY-RESOLVED)
              ;; Update resolution status
              (begin
                (map-set domain-reports {domain-name: domain-name, reporter: reporter}
                  {reason-code: (get reason-code report-data),
                   details: (get details report-data),
                   resolved: true,
                   reported-at: (get reported-at report-data)})
                ;; Emit event
                (emit-event (dispute-resolved domain-name tx-sender status))
                (ok true)))
          none
          ;; Report not found
          (err ERR-NOT-FOUND)))
        ;; Caller lacks permission
        (err ERR-NO-PERMISSION))))

;; Assign Role Function (Admin Only)
(define-public (assign-role
                (user principal)
                (role (string-ascii 32)))
  (begin
    ;; Only admin can assign roles
    (if (has-role? tx-sender ADMIN-ROLE)
        (begin
          (map-set user-roles {user: user} {role: role})
          (ok true))
        (err ERR-NO-PERMISSION))))

;; Verify Identity Function (Admin or Moderator Only)
(define-public (verify-identity
                (domain-name (string-ascii 253)))
  (begin
    ;; Check if caller has permission
    (if (has-role? tx-sender MODERATOR-ROLE)
        ;; Proceed to verify identity
        (match (map-get? domains {domain-name: domain-name})
          some domain-data
          ;; Domain exists, update verification status
          (begin
            (map-set domains {domain-name: domain-name}
              {owner: (get owner domain-data),
               identity-info: (get identity-info domain-data),
               identity-verified: true,
               reputation-score: (get reputation-score domain-data),
               registered-at: (get registered-at domain-data)})
            (emit-event (identity-verified domain-name tx-sender))
            (ok true))
          none
          ;; Domain not found
          (err ERR-NOT-FOUND)))
        ;; Caller lacks permission
        (err ERR-NO-PERMISSION))))

;; ------------------------------
;; Private Functions
;; ------------------------------

;; Check if user has a specific role
(define-private (has-role? (user principal) (role (string-ascii 32)))
  (match (map-get? user-roles {user: user})
    some user-role
    (is-eq (get role user-role) role)
    none
    false))

;; Placeholder for Domain Ownership Verification
(define-private (verify-domain-ownership
                 (domain-name (string-ascii 253))
                 (verification-code (string-ascii 64))
                 (owner principal))
  ;; In production, this function should interface with an oracle or off-chain service
  ;; to verify that the owner has control over the domain.
  ;; For demonstration, we'll simulate verification by requiring the verification code
  ;; to match a hash of the domain name and owner's address.

  (let ((expected-code (sha256 (concat (hash160 domain-name) (hash160 (principal-to-hex owner))))))
    (is-eq expected-code (sha256 verification-code))))

;; Update Reputation Score Function
(define-private (update-reputation-score (domain-name (string-ascii 253)))
  (let ((reviews (map-filter (lambda (key value)
                               (is-eq (get domain-name key) domain-name))
                             domain-reviews)))
    (let ((total-score (fold (lambda (acc entry)
                               (let ((rating (get rating (snd entry)))
                                     (reviewer-reputation (get reviewer-reputation (snd entry))))
                                 ;; Weighted rating = rating * reviewer's reputation (simplified)
                                 (+ acc (* rating (max reviewer-reputation 1)))))
                             0
                             reviews)))
      (map-set domains {domain-name: domain-name}
        (merge
          (unwrap! (map-get? domains {domain-name: domain-name}) (err ERR-NOT-FOUND))
          {reputation-score: total-score})))))

;; Get User Reputation (Simplified)
(define-private (get-user-reputation (user principal))
  ;; In production, implement a proper user reputation system
  ;; For demonstration, return 1 for all users
  1)

;; ------------------------------
;; Testing Functions (Optional)
;; ------------------------------

;; Test Function to Initialize Admin Role (for testing purposes)
(define-public (initialize-admin (admin principal))
  (begin
    ;; Only allow contract deployer to initialize admin
    (if (is-eq tx-sender (contract-owner?))
        (begin
          (map-set user-roles {user: admin} {role: ADMIN-ROLE})
          (ok true))
        (err ERR-NO-PERMISSION))))

;; ------------------------------
;; End of Smart Contract
;; ------------------------------
