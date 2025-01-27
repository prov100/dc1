INSERT INTO `users`
	  (uuid4,
first_name,
last_name,
email,
username,
active,
password,
status_code,
created_at,
updated_at,
created_by_user_id,
updated_by_user_id) VALUES (UNHEX(REPLACE('ca2862cc-97ae-4705-b372-de87762b22f6','-','')),'TskZoQ','sprov100','sprov100@gmail.com','sprov100@gmail.com', true,'$2a$10$rpUAIHIHbmjS/5qcBJbqheLXSt0Czvi4HBCbNFmf8SsITJgRTOnmq','active','2019-07-23 10:04:26','2019-07-23 10:04:26',1,1),(UNHEX(REPLACE('10866c00-ee4a-4a93-aa33-d97743f6b1f1','-','')), 'TskZoQ2','sprov200','sprov200@gmail.com', 'sprov200@gmail.com', true,'$2a$10$rpUAIHIHbmjS/5qcBJbqheLXSt0Czvi4HBCbNFmf8SsITJgRTOnmq','active','2019-07-23 10:04:26','2019-07-23 10:04:26',1,1);

INSERT INTO `user_roles`
	  (u_role,
user_id) VALUES ('co_admin',1),('admin',2);
