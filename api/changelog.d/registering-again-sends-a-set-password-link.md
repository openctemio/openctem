### Fixed: registering again with an unverified address emails a set-password link

- A user whose verification email was lost or expired had no way back:
  registering again gave the usual answer and sent nothing, and sign-in said
  "Email is not verified". Registering again with an address whose password
  account never verified now emails that address a set-password link (the
  forgot-password link). Following it verifies the address and replaces the
  password. The answer and its timing stay the same as for any address.
- Security: the account cannot be kept by whoever registered the address
  first with their own password (account pre-hijacking): the owner's link
  replaces that password. A verified account and a new address get nothing new.
