### Fixed: Word and Excel downloads open again

- The web API proxy decoded every response that was not on a short list of binary types as text, which corrupted DOCX and XLSX files: the pentest starter template, uploaded templates, template previews and Word reports downloaded from the console did not open. Only JSON and text responses are decoded now; every other type is passed through byte for byte.
