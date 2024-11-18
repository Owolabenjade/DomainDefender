(define-constant ERR-NOT-FOUND u100)
(define-constant ERR-UNAUTHORIZED u101)
(define-constant ERR-DOMAIN-ALREADY-REGISTERED u102)
(define-constant ERR-INVALID-DATA u103)

;; Define the structure for domain information
(define-data-var domains (map (string-ascii 253) DomainData) {})

;; Define the structure for storing reviews
(define-data-var domain-reviews (map (string-ascii 253) (list ReviewData)) {})

;; Define the structure for storing reports
(define-data-var domain-reports (map (string-ascii 253) (list ReportData)) {})

;; Structure for domain data
(define-map domains
  ((domain-name (string-ascii 253)))       ;; Key: Domain name (max length 253 characters as per domain standards)
  ((owner principal)                       ;; Owner's principal address
   (identity-info (string-utf8 512))       ;; Identity information in UTF-8 format
   (reputation-score int)                  ;; Calculated reputation score
   (registered-at uint)))                  ;; Timestamp of registration

;; Structure for review data
(define-map domain-reviews
  ((domain-name (string-ascii 253))        ;; Key: Domain name
   (reviewer principal))                   ;; Key: Reviewer's principal address
  ((rating int)                            ;; Rating given by the reviewer
   (comment (string-utf8 256))             ;; Optional comment
   (reviewed-at uint)))                    ;; Timestamp of the review

;; Structure for report data
(define-map domain-reports
  ((domain-name (string-ascii 253))        ;; Key: Domain name
   (reporter principal))                   ;; Key: Reporter's principal address
  ((reason-code int)                       ;; Code representing the reason for report
   (details (string-utf8 256))             ;; Optional details about the report
   (reported-at uint)))                    ;; Timestamp of the report
