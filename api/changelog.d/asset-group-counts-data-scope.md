### Security: asset group counts follow the reader data scope

- The asset group list, a group, the group stats and the group returned after a change now count only the assets the reader may see: asset count, per-kind counts, risk score and finding count. A member restricted to some assets used to see tenant-wide numbers (L-18), and could probe them with the risk and has-findings filters. Owners, administrators and full-data roles see the whole group as before.
