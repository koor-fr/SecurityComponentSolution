USE [master]
GO
/****** Object:  Database [SecurityComponent]    Script Date: 05/12/2018 11:39:12 ******/
CREATE DATABASE [SecurityComponent]
 CONTAINMENT = NONE
 ON  PRIMARY 
( NAME = N'SecurityComponent', FILENAME = N'C:\Program Files\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQL\DATA\SecurityComponent.mdf' , SIZE = 8192KB , MAXSIZE = UNLIMITED, FILEGROWTH = 65536KB )
 LOG ON 
( NAME = N'SecurityComponent_log', FILENAME = N'C:\Program Files\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQL\DATA\SecurityComponent_log.ldf' , SIZE = 8192KB , MAXSIZE = 2048GB , FILEGROWTH = 65536KB )
GO
ALTER DATABASE [SecurityComponent] SET COMPATIBILITY_LEVEL = 140
GO
IF (1 = FULLTEXTSERVICEPROPERTY('IsFullTextInstalled'))
begin
EXEC [SecurityComponent].[dbo].[sp_fulltext_database] @action = 'enable'
end
GO
ALTER DATABASE [SecurityComponent] SET ANSI_NULL_DEFAULT OFF 
GO
ALTER DATABASE [SecurityComponent] SET ANSI_NULLS OFF 
GO
ALTER DATABASE [SecurityComponent] SET ANSI_PADDING OFF 
GO
ALTER DATABASE [SecurityComponent] SET ANSI_WARNINGS OFF 
GO
ALTER DATABASE [SecurityComponent] SET ARITHABORT OFF 
GO
ALTER DATABASE [SecurityComponent] SET AUTO_CLOSE OFF 
GO
ALTER DATABASE [SecurityComponent] SET AUTO_SHRINK OFF 
GO
ALTER DATABASE [SecurityComponent] SET AUTO_UPDATE_STATISTICS ON 
GO
ALTER DATABASE [SecurityComponent] SET CURSOR_CLOSE_ON_COMMIT OFF 
GO
ALTER DATABASE [SecurityComponent] SET CURSOR_DEFAULT  GLOBAL 
GO
ALTER DATABASE [SecurityComponent] SET CONCAT_NULL_YIELDS_NULL OFF 
GO
ALTER DATABASE [SecurityComponent] SET NUMERIC_ROUNDABORT OFF 
GO
ALTER DATABASE [SecurityComponent] SET QUOTED_IDENTIFIER OFF 
GO
ALTER DATABASE [SecurityComponent] SET RECURSIVE_TRIGGERS OFF 
GO
ALTER DATABASE [SecurityComponent] SET  DISABLE_BROKER 
GO
ALTER DATABASE [SecurityComponent] SET AUTO_UPDATE_STATISTICS_ASYNC OFF 
GO
ALTER DATABASE [SecurityComponent] SET DATE_CORRELATION_OPTIMIZATION OFF 
GO
ALTER DATABASE [SecurityComponent] SET TRUSTWORTHY OFF 
GO
ALTER DATABASE [SecurityComponent] SET ALLOW_SNAPSHOT_ISOLATION OFF 
GO
ALTER DATABASE [SecurityComponent] SET PARAMETERIZATION SIMPLE 
GO
ALTER DATABASE [SecurityComponent] SET READ_COMMITTED_SNAPSHOT OFF 
GO
ALTER DATABASE [SecurityComponent] SET HONOR_BROKER_PRIORITY OFF 
GO
ALTER DATABASE [SecurityComponent] SET RECOVERY FULL 
GO
ALTER DATABASE [SecurityComponent] SET  MULTI_USER 
GO
ALTER DATABASE [SecurityComponent] SET PAGE_VERIFY CHECKSUM  
GO
ALTER DATABASE [SecurityComponent] SET DB_CHAINING OFF 
GO
ALTER DATABASE [SecurityComponent] SET FILESTREAM( NON_TRANSACTED_ACCESS = OFF ) 
GO
ALTER DATABASE [SecurityComponent] SET TARGET_RECOVERY_TIME = 60 SECONDS 
GO
ALTER DATABASE [SecurityComponent] SET DELAYED_DURABILITY = DISABLED 
GO
EXEC sys.sp_db_vardecimal_storage_format N'SecurityComponent', N'ON'
GO
ALTER DATABASE [SecurityComponent] SET QUERY_STORE = OFF
GO
USE [SecurityComponent]
GO
/****** Object:  Table [dbo].[T_ROLES]    Script Date: 05/12/2018 11:39:12 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[T_ROLES](
	[IdRole] [int] IDENTITY(1,1) NOT NULL,
	[RoleName] [text] NOT NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[T_USER_ROLES]    Script Date: 05/12/2018 11:39:12 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[T_USER_ROLES](
	[IdUser] [int] NOT NULL,
	[IdRole] [int] NOT NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[T_USERS]    Script Date: 05/12/2018 11:39:12 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[T_USERS](
	[IdUser] [int] IDENTITY(1,1) NOT NULL,
	[Login] [text] NOT NULL,
	[Password] [text] NOT NULL,
	[ConnectionNumber] [int] NOT NULL,
	[LastConnection] [datetime] NULL,
	[ConsecutiveErrors] [int] NOT NULL,
	[Disabled] [bit] NOT NULL,
	[FirstName] [text] NULL,
	[LastName] [text] NULL,
	[Email] [text] NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
SET IDENTITY_INSERT [dbo].[T_ROLES] ON 

INSERT [dbo].[T_ROLES] ([IdRole], [RoleName]) VALUES (1, N'admin')
SET IDENTITY_INSERT [dbo].[T_ROLES] OFF
INSERT [dbo].[T_USER_ROLES] ([IdUser], [IdRole]) VALUES (4, 1)
SET IDENTITY_INSERT [dbo].[T_USERS] ON 

INSERT [dbo].[T_USERS] ([IdUser], [Login], [Password], [ConnectionNumber], [LastConnection], [ConsecutiveErrors], [Disabled], [FirstName], [LastName], [Email]) VALUES (4, N'root', N'admin', 241, CAST(N'2018-12-05T11:26:52.430' AS DateTime), 0, 0, NULL, NULL, NULL)
INSERT [dbo].[T_USERS] ([IdUser], [Login], [Password], [ConnectionNumber], [LastConnection], [ConsecutiveErrors], [Disabled], [FirstName], [LastName], [Email]) VALUES (5, N'bond', N'007', 0, NULL, 0, 0, NULL, NULL, NULL)
SET IDENTITY_INSERT [dbo].[T_USERS] OFF
ALTER TABLE [dbo].[T_USERS] ADD  CONSTRAINT [DF_T_USERS2_ConnectionNumber]  DEFAULT ((0)) FOR [ConnectionNumber]
GO
ALTER TABLE [dbo].[T_USERS] ADD  CONSTRAINT [DF_T_USERS]  DEFAULT (NULL) FOR [LastConnection]
GO
ALTER TABLE [dbo].[T_USERS] ADD  CONSTRAINT [DF_T_USERS2_ConsecutiveErrors]  DEFAULT ((0)) FOR [ConsecutiveErrors]
GO
ALTER TABLE [dbo].[T_USERS] ADD  CONSTRAINT [DF_T_USERS2_Disabled]  DEFAULT ((0)) FOR [Disabled]
GO
USE [master]
GO
ALTER DATABASE [SecurityComponent] SET  READ_WRITE 
GO
