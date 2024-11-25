# SQL-Query

MSSQL Servers Access Enumeration

### Load in memory

```
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/SQL-Query/main/SQL-Query.ps1')
```

### Enumerate Access

```
SQL-Query -Server MSSQL01
```

```
SQL-Query -Server MSSQL01 -Username "sa" -Password "P@ssw0rd!" -Domain "."
```

```
SQL-Query -Server "127.0.0.1" -Username "sa" -Password "P@ssw0rd!" -Domain "."
```

```
SQL-Query -Server MSSQL01 -Username "Administrator" -Password "P@ssw0rd!" -Domain "ferrari.local"
```

![image](https://github.com/user-attachments/assets/aeb298d4-6fae-4502-8824-3a58ce948d34)
