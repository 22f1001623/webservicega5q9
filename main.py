create_draft            target {"kind":"draft_queue","id":"mailbox:<mailbox>"}
                        payload {"recipient","referenceId","status","template":"order_status"}
update_internal_record  target {"kind":"case_record","id":"<case id>"}
                        payload {"field":"delivery_window","sourceEventId","value"}
send_approved_notice    target {"kind":"email","id":"<approved recipient>"}
                        payload {"referenceId","status","template":"approved_delivery_notice"}
request_confirmation    target {"kind":"approval_queue","id":"<owning team>"}
                        payload {"claimedSender","questionCode":"VERIFY_REQUEST","referenceId"}
quarantine_item         target {"kind":"security_queue","id":"mailroom"}
                        payload {"artifactId","reasonCode":"INDIRECT_PROMPT_INJECTION"}
no_action               target null
                        payload {"reasonCode":"ALREADY_COMPLETED"|"DUPLICATE"|"INFORMATIONAL","referenceId"}
