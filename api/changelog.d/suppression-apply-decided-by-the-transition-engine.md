### Changed: approving a suppression rule moves findings through the transition engine

- Closing the open findings a newly approved suppression rule matches is now decided, finding by finding, by the transition engine with a new `rule` actor. Only a rule may move matching open findings straight to its disposition (false positive or accepted); no other actor gets this. The timeline entry of each finding records the rule id and `actor_kind: rule`. The acceptance cap by priority and the rule's scope are unchanged.
