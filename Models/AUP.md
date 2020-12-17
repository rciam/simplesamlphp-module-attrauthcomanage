AUP Model stored in the state, `$state['rciamAttributes']['aup']`

```bash
{
  "Version":"1.0",
  "aup":
  [
    {
      "id": "<cm_co_terms_and_conditions::id>",
      "description": "<cm_co_terms_and_conditions::description>",
      "url": "cm_co_terms_and_conditions::url",
      "modified": "<cm_co_terms_and_conditions::modified>",
      "vo":
      {
        "id": "<cm_cous::id>",
        "name": "<cm_cous::name>"
      },
      "version": "<cm_co_terms_and_conditions::revision>",
      "agreed":
      {
        "id": "<cm_co_t_and_c_agreements::id>",
        "aup_id": "<cm_co_t_and_c_agreements::co_terms_and_conditions_id>",
        "date": "<cm_co_t_and_c_agreements::agreement_time>",
        "version": "<cm_co_terms_and_conditions::cm_co_terms_and_conditions_id::revision>"
      }
    }
  ]
}
```
<pre>
* id              Id of the AUP in the Registry Database
* description     Short description
* url             URL  containing the HTML representation of the AUP content
* modified        Date the AUP was last modified
* vo
  * id            Id of the VO associated with this AUP
  * name          Name of the VO
* verson          Current version of the AUP
* agreed
  * id            Id of the AUP agreement
  * aup_id        Id of the last agreed AUP
  * date          The date the AUP agreement was signed
  * version       The version of the agreed AUP
</pre>