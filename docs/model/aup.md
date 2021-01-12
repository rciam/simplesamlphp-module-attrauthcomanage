AUP Model is stored in the state, `$state['rciamAttributes']['aup']`. In addition, the model encapsulates two additional structures, the `vo` and the `agreed` ones, under the respective fields. Both of these directly correlate to the AUP model.
* `vo` structure encompasses VO associated information with this AUP
* `agreed` structure encompasses information on the last agreement for this AUP

:warning: `vo` field is set to `null` when the AUP is not associated with any VO

:warning: `agreed` field is set to `null` if the user hasn't agreed with any version of this AUP

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
        "aupId": "<cm_co_t_and_c_agreements::co_terms_and_conditions_id>",
        "date": "<cm_co_t_and_c_agreements::agreement_time>",
        "version": "<cm_co_terms_and_conditions::cm_co_terms_and_conditions_id::revision>"
      }
    }
  ]
}
```
<pre>
* id              Id of the AUP in the COmanage Registry
* description     Short description of the AUP
* url             URL pointing to the AUP webpage
* modified        Date when the AUP was last modified in the COmanage Registry
* vo              VO associated information with this AUP
  * id            Id of the VO associated with this AUP
  * name          Name of the VO associated with this AUP
* version         Current version of the AUP
* agreed          Information on the last agreement for this AUP
  * id            Id of the AUP agreement
  * aupId         Id of the last agreed AUP
  * date          Date when the AUP agreement was signed
  * version       Version of the agreed AUP
</pre>
