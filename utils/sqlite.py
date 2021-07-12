#!/usr/bin/env python3

import sqlite3

# Database init.
conn = sqlite3.connect('../../zeroscan.db')
c = conn.cursor()


def create_table_zeroscan():
	''' Create table '''
	try:
		with conn:
			c.execute("""CREATE TABLE Zeroscan(
				Hostname text,
				IPAddress text,
				CVE_2020_1472 text,
				MS_PAR text, 
				MS_RPRN text,
				SMBv2_Security text
				)""")
	except sqlite3.OperationalError:
		pass


def insert_data(hostname, ipaddress, CVE_2020_1472, MS_PAR, MS_RPRN, smbv2_security):
	''' Insert data '''
	with conn:
		c.execute("INSERT INTO Zeroscan VALUES (:hostname, :ipaddress, :CVE_2020_1472, :MS_PAR, :MS_RPRN, :smbv2_security)",
		 {'hostname': hostname, 'ipaddress': ipaddress, 'CVE_2020_1472': CVE_2020_1472, 'MS_PAR': MS_PAR, 'MS_RPRN': MS_RPRN, 'smbv2_security': smbv2_security})


def update_CVE_2020_1472(hostname, ipaddress, CVE_2020_1472):
	''' Update CVE_2020_1472 '''
	with conn:
		c.execute("UPDATE Zeroscan SET CVE_2020_1472=:CVE_2020_1472 WHERE hostname=:hostname AND ipaddress=:ipaddress",
		 {'hostname': hostname, 'ipaddress': ipaddress, 'CVE_2020_1472': CVE_2020_1472})


def update_smbv2_security(ipaddress, smbv2_security):
	''' Update SMBv2 Signing '''
	with conn:
		c.execute("UPDATE Zeroscan SET smbv2_security=:smbv2_security WHERE ipaddress=:ipaddress",
		 {'ipaddress': ipaddress, 'smbv2_security': smbv2_security})


def update_MS_PAR(ipaddress, MS_PAR):
	''' Update  MS_PAR '''
	with conn:
		c.execute("UPDATE Zeroscan SET MS_PAR=:MS_PAR WHERE ipaddress=:ipaddress",
		 {'ipaddress': ipaddress, 'MS_PAR' : MS_PAR})


def update_MS_RPRN(ipaddress, MS_RPRN):
	''' Update MS_RPRN '''
	with conn:
		c.execute("UPDATE Zeroscan SET MS_RPRN=:MS_RPRN WHERE ipaddress=:ipaddress",
		 {'ipaddress': ipaddress, 'MS_RPRN' : MS_RPRN})


def get_data(tablename):
	''' Fetch all table data '''
	c.execute("SELECT * FROM Zeroscan")

	return c.fetchall()


def drop_table(tablename):
	''' Drop table '''
	try:
		with conn:
			c.execute(f"DROP TABLE {tablename}")
	except sqlite3.OperationalError as e:
		pass