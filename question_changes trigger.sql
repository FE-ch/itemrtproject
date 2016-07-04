DELIMITER $$

DROP TRIGGER IF EXISTS `question_updates`$$
CREATE
	TRIGGER `question_updates` AFTER UPDATE 
	ON `itemrtdb_question` 
	FOR EACH ROW BEGIN

		SET @changesummary = CONCAT('Question ', NEW.id);
    
		INSERT INTO changes (data) VALUES (@changesummary);		
    END$$

DELIMITER ;

DELIMITER $$

DROP TRIGGER IF EXISTS `answer_updates`$$
CREATE
	TRIGGER `answer_updates` AFTER UPDATE 
	ON `itemrtdb_answer` 
	FOR EACH ROW BEGIN

		SET @changesummary = CONCAT('Answer', NEW.id,' for qn ', NEW.question_id);
    
		INSERT INTO changes (data) VALUES (@changesummary);		
    END$$

DELIMITER ;

DELIMITER $$

DROP TRIGGER IF EXISTS `solution_updates`$$
CREATE
	TRIGGER `solution_updates` AFTER UPDATE 
	ON `itemrtdb_solution` 
	FOR EACH ROW BEGIN

		SET @changesummary = CONCAT('Solution for question ', NEW.question_id);
    
		INSERT INTO changes (data) VALUES (@changesummary);		
    END$$

DELIMITER ;