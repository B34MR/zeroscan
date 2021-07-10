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
				SMBv2_Signing text
				)""")
	except sqlite3.OperationalError:
		pass


def insert_data(hostname, ipaddress, CVE_2020_1472, smbv2_signing):
	''' Insert data '''
	with conn:
		c.execute("INSERT INTO Zeroscan VALUES (:hostname, :ipaddress, :CVE_2020_1472, :smbv2_signing)",
		 {'hostname': hostname, 'ipaddress': ipaddress, 'CVE_2020_1472': CVE_2020_1472, 'smbv2_signing': smbv2_signing})


def update_CVE_2020_1472(hostname, ipaddress, CVE_2020_1472):
	''' Update CVE_2020_1472 '''
	with conn:
		c.execute("UPDATE Zeroscan SET CVE_2020_1472=:CVE_2020_1472 WHERE hostname=:hostname AND ipaddress=:ipaddress",
		 {'hostname': hostname, 'ipaddress': ipaddress, 'CVE_2020_1472': CVE_2020_1472})


def update_smbv2_signing(ipaddress, smbv2_signing):
	''' Update SMBv2 Signing '''
	with conn:
		c.execute("UPDATE Zeroscan SET smbv2_signing=:smbv2_signing WHERE ipaddress=:ipaddress",
		 {'ipaddress': ipaddress, 'smbv2_signing': smbv2_signing})


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